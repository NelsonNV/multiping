use chrono::Local;
use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{Clear, ClearType},
};
use futures::future::join_all;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::{stdout, BufWriter, Write},
    net::IpAddr,
    sync::Arc,
};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::{net::lookup_host, sync::Mutex, time};

#[derive(Deserialize, Clone)]
struct HostConfig {
    dns: Option<String>,
    ip: String,
    alt_ips: Option<Vec<String>>,
    port: Option<u16>,
}

#[derive(Deserialize)]
struct IPs(BTreeMap<String, HostConfig>);

#[tokio::main]
async fn main() {
    let mut stdout = stdout();
    execute!(stdout, Clear(ClearType::All)).unwrap();
    let ips = load_ips("ips.json");
    let log_filename = create_log_file();
    let total_packet_loss = Arc::new(Mutex::new(0));
    let mut request_count = 0;

    loop {
        request_count += 1;
        let results = perform_checks(&ips, &log_filename, &total_packet_loss).await;
        display_results(&mut stdout, request_count, &total_packet_loss, &results).await;
        time::sleep(time::Duration::from_millis(500)).await;
    }
}

fn load_ips(filename: &str) -> IPs {
    let data = fs::read_to_string(filename).expect("No se pudo leer el archivo JSON");
    serde_json::from_str(&data).expect("Error al parsear el JSON")
}

fn create_log_file() -> String {
    let filename = format!("log_{}.csv", Local::now().format("%d-%m-%Y_%H-%M-%S"));
    let mut log_file = BufWriter::new(fs::File::create(&filename).expect("Error creando log"));
    writeln!(
        log_file,
        "timestamp,host,tipo,direccion,latencia,port,pkt,estado"
    )
    .unwrap();
    log_file.flush().unwrap();
    filename
}

async fn perform_checks(
    ips: &IPs,
    log_filename: &str,
    total_packet_loss: &Arc<Mutex<u32>>,
) -> Vec<(String, String, String, String, String, String, String)> {
    let mut tasks = vec![];
    for (host, config) in &ips.0 {
        let total_loss_clone = Arc::clone(total_packet_loss);
        let log_filename_clone = log_filename.to_string();
        add_ping_tasks(
            host,
            config,
            &mut tasks,
            total_loss_clone,
            log_filename_clone,
        );
    }
    join_all(tasks)
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect()
}

fn add_ping_tasks(
    host: &String,
    config: &HostConfig,
    tasks: &mut Vec<
        tokio::task::JoinHandle<(String, String, String, String, String, String, String)>,
    >,
    total_loss_clone: Arc<Mutex<u32>>,
    log_filename_clone: String,
) {
    let parsed_ip = parse_ip_and_port(&config.ip, config.port);
    tasks.push(tokio::spawn(check_ping(
        host.clone(),
        "IP".to_string(),
        parsed_ip.0,
        parsed_ip.1,
        total_loss_clone.clone(),
        log_filename_clone.clone(),
    )));
    if let Some(dns) = &config.dns {
        let parsed_dns = parse_ip_and_port(dns, config.port);
        tasks.push(tokio::spawn(check_ping(
            host.clone(),
            "DNS".to_string(),
            parsed_dns.0,
            parsed_dns.1,
            total_loss_clone.clone(),
            log_filename_clone.clone(),
        )));
    }
    if let Some(alt_ips) = &config.alt_ips {
        for alt_ip in alt_ips {
            let parsed_alt_ip = parse_ip_and_port(alt_ip, config.port);
            tasks.push(tokio::spawn(check_ping(
                host.clone(),
                "Alt IP".to_string(),
                parsed_alt_ip.0,
                parsed_alt_ip.1,
                total_loss_clone.clone(),
                log_filename_clone.clone(),
            )));
        }
    }
}

async fn display_results(
    stdout: &mut std::io::Stdout,
    request_count: u32,
    total_packet_loss: &Arc<Mutex<u32>>,
    results: &[(String, String, String, String, String, String, String)],
) {
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0)).unwrap();
    println!(
        "Peticiones realizadas: {} | Paquetes perdidos globalmente: {}\n",
        request_count,
        *total_packet_loss.lock().await
    );
    println!(
        "{:<15} | {:<10} | {:<20} | {:<8} | {:<6} | {:<3} | {:<10}",
        "Host", "Tipo", "Dirección", "Latencia", "Port", "Pkt", "Estado"
    );
    println!("{}", "-".repeat(89));
    for row in results {
        println!(
            "{:<15} | {:<10} | {:<20} | {:<8} | {:<6} | {:<3} | {:<10}",
            row.0, row.1, row.2, row.3, row.4, row.5, row.6
        );
    }
    stdout.flush().unwrap();
}

async fn check_ping(
    host: String,
    tipo: String,
    direccion: String,
    port: Option<u16>,
    total_loss: Arc<Mutex<u32>>,
    log_filename: String,
) -> (String, String, String, String, String, String, String) {

    let addr = match resolve_hostname(&direccion).await {
        Some(ip) => ip,
        None => {
            return (
                host,
                tipo,
                direccion,
                "N/A".to_string(),
                port.unwrap_or(0).to_string(),
                "-".to_string(),
                "🔴".to_string(),
            );
        }
    };

    let client = Client::new(&Config::default()).unwrap();
    let mut pinger = client.pinger(addr, PingIdentifier(0)).await;
    let (losses, total_time) = ping_loop(&mut pinger).await;
    let avg_ping = calculate_avg_ping(losses, total_time);
    let status_icon = determine_status_icon(losses);
    *total_loss.lock().await += losses;
    log_ping_result(
        &log_filename,
        &host,
        &tipo,
        &direccion,
        &avg_ping,
        port,
        losses,
        &status_icon,
    );
    (
        host,
        tipo,
        direccion,
        avg_ping,
        port.unwrap_or(0).to_string(),
        losses.to_string(),
        status_icon,
    )
}

async fn ping_loop(pinger: &mut surge_ping::Pinger) -> (u32, f64) {
    let mut losses = 0;
    let mut total_time = 0.0;
    for i in 0..2 {
        if let Ok((_, rtt)) = pinger.ping(PingSequence(i as u16), &[0]).await {
            total_time += rtt.as_millis() as f64;
        } else {
            losses += 1;
        }
        time::sleep(time::Duration::from_millis(50)).await;
    }
    (losses, total_time)
}

fn calculate_avg_ping(losses: u32, total_time: f64) -> String {
    if losses < 2 {
        format!("{:.1}ms", total_time / (2 - losses) as f64)
    } else {
        "N/A".to_string()
    }
}

fn determine_status_icon(losses: u32) -> String {
    ["🟢", "🟡", "🔴"][losses as usize].to_string()
}

fn parse_ip_and_port(ip_str: &str, default_port: Option<u16>) -> (String, Option<u16>) {
    ip_str.split_once(':').map_or(
        (ip_str.to_string(), default_port.or(Some(443))),
        |(ip, port)| (ip.to_string(), port.parse().ok()),
    )
}

async fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    if let Ok(mut addrs) = lookup_host(format!("{}:80", hostname)).await {
        if let Some(addr) = addrs.find(|a| a.ip().is_ipv4()) {
            return Some(addr.ip());
        }
    }
    None
}

fn log_ping_result(
    log_filename: &str,
    host: &str,
    tipo: &str,
    direccion: &str,
    avg_ping: &str,
    port: Option<u16>,
    losses: u32,
    status_icon: &str,
) {
    let timestamp = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let mut log_file = fs::OpenOptions::new()
        .append(true)
        .open(log_filename)
        .expect("Error abriendo log");
    writeln!(
        log_file,
        "{},{},{},{},{},{},{},{}",
        timestamp,
        host,
        tipo,
        direccion,
        avg_ping,
        port.unwrap_or(0),
        losses,
        status_icon
    )
    .expect("Error escribiendo en el log");
}
