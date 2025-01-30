
use std::{fs, collections::BTreeMap, sync::Arc, net::IpAddr, io::Write};
use serde::Deserialize;
use tokio::{task, time, sync::Mutex, net::lookup_host};
use crossterm::{execute, terminal::{Clear, ClearType}, cursor::MoveTo};
use std::io::{stdout, BufWriter};
use futures::future::join_all;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use chrono::Local;

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

    let data = fs::read_to_string("ips.json").expect("No se pudo leer el archivo JSON");
    let ips: IPs = serde_json::from_str(&data).expect("Error al parsear el JSON");

    let mut request_count = 0;
    let total_packet_loss = Arc::new(Mutex::new(0));

    let start_time = Local::now().format("%d-%m-%Y_%H-%M-%S").to_string();
    let log_filename = format!("log_{}.csv", start_time);
    let mut log_file = BufWriter::new(fs::File::create(&log_filename).expect("Error creando log"));

    writeln!(log_file, "timestamp,host,tipo,direccion,latencia,port,pkt,estado").expect("Error escribiendo en el archivo log");
    log_file.flush().expect("Error al guardar log");

    loop {
        request_count += 1;
        let mut tasks = vec![];

        for (host, config) in ips.0.clone() {
            let total_loss_clone = Arc::clone(&total_packet_loss);
            let log_filename_clone = log_filename.clone();

            let parsed_ip = parse_ip_and_port(&config.ip, config.port);
            let port = parsed_ip.1;

            tasks.push(tokio::spawn(check_ping(
                host.clone(), "IP".to_string(), parsed_ip.0.clone(), port, total_loss_clone.clone(), log_filename_clone.clone()
            )));

            if let Some(dns) = config.dns.clone() {
                let parsed_dns = parse_ip_and_port(&dns, config.port);
                tasks.push(tokio::spawn(check_ping(
                    host.clone(), "DNS".to_string(), parsed_dns.0, parsed_dns.1, total_loss_clone.clone(), log_filename_clone.clone()
                )));
            }

            if let Some(alt_ips) = config.alt_ips.clone() {
                for alt_ip in alt_ips {
                    let parsed_alt_ip = parse_ip_and_port(&alt_ip, config.port);
                    tasks.push(tokio::spawn(check_ping(
                        host.clone(), "Alt IP".to_string(), parsed_alt_ip.0, parsed_alt_ip.1, total_loss_clone.clone(), log_filename_clone.clone()
                    )));
                }
            }
        }

        let results = join_all(tasks).await;
        let mut output_table: Vec<(String, String, String, String, String, String, String)> = vec![];

        for result in results {
            if let Ok(res) = result {
                output_table.push(res);
            }
        }

        execute!(stdout, Clear(ClearType::All), MoveTo(0, 0)).unwrap();
        println!("Peticiones realizadas: {} | Paquetes perdidos globalmente: {}\n", request_count, *total_packet_loss.lock().await);

        println!("{:<15} | {:<10} | {:<20} | {:<8} | {:<6} | {:<3} | {:<10}", "Host", "Tipo", "Dirección", "Latencia", "Port", "Pkt", "Estado");
        println!("{}", "-".repeat(89));

        for row in output_table {
            println!("{:<15} | {:<10} | {:<20} | {:<8} | {:<6} | {:<3} | {:<10}", row.0, row.1, row.2, row.3, row.4, row.5, row.6);
        }
        stdout.flush().unwrap();

        time::sleep(time::Duration::from_millis(500)).await;
    }
}

async fn check_ping(host: String, tipo: String, direccion: String, port: Option<u16>, total_loss: Arc<Mutex<u32>>, log_filename: String) -> (String, String, String, String, String, String, String) {
    let addr = match resolve_hostname(&direccion).await {
        Some(ip) => ip,
        None => return (host, tipo, direccion, "N/A".to_string(), port.unwrap_or(0).to_string(), "-".to_string(), "🔴".to_string()),
    };

    let client = Client::new(&Config::default()).expect("Error al crear cliente ICMP");

    let mut pinger = client.pinger(addr, PingIdentifier(0)).await;
    let mut losses = 0;
    let mut total_time = 0.0;
    let count = 2;

    for i in 0..count {
        let seq = PingSequence(i as u16);
        match pinger.ping(seq, &[0]).await {
            Ok((_, rtt)) => {
                total_time += rtt.as_millis() as f64;
            }
            Err(_) => {
                losses += 1;
            }
        }
        time::sleep(time::Duration::from_millis(50)).await;
    }

    let avg_ping = if count - losses > 0 {
        format!("{:.1}ms", total_time / ((count - losses) as f64))
    } else {
        "N/A".to_string()
    };

    let status_icon = match losses {
        0 => "🟢".to_string(),
        1 => "🟡".to_string(),
        _ => "🔴".to_string(),
    };

    let mut total_loss_guard = total_loss.lock().await;
    *total_loss_guard += losses;

    let timestamp = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let mut log_file = fs::OpenOptions::new().append(true).open(&log_filename).expect("Error abriendo log");
    writeln!(log_file, "{},{},{},{},{},{},{},{}", timestamp, host, tipo, direccion, avg_ping, port.unwrap_or(0), losses, status_icon).expect("Error escribiendo en el log");

    (host, tipo, direccion, avg_ping, port.unwrap_or(0).to_string(), losses.to_string(), status_icon)
}

async fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    if let Ok(mut addrs) = lookup_host(format!("{}:80", hostname)).await {
        if let Some(addr) = addrs.find(|a| a.ip().is_ipv4()) {
            return Some(addr.ip());
        }
    }
    None
}

fn parse_ip_and_port(ip_str: &str, default_port: Option<u16>) -> (String, Option<u16>) {
    if let Some((ip, port)) = ip_str.split_once(':') {
        if let Ok(port_num) = port.parse::<u16>() {
            return (ip.to_string(), Some(port_num));
        }
    }
    (ip_str.to_string(), default_port.or(Some(443)))
}
