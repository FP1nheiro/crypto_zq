// czq-pack-gui — janela gráfica para criptografar uma pasta de client inteira
// (RFC §15). Seleciona a pasta do client (entrada) e a pasta de saída; varre tudo
// recursivamente, particiona .spr em chunks/, e espelha a árvore criptografada.
// Envolve o binário `czq-pack packdir`. Abre com duplo-clique.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 660.0])
            .with_min_inner_size([600.0, 480.0])
            .with_title("CZQ Packer"),
        ..Default::default()
    };
    eframe::run_native("CZQ Packer", options, Box::new(|_cc| Box::new(App::new())))
}

struct App {
    in_dir: String,
    out_dir: String,
    install_dir: String, // opcional: src/framework/core/czq do client (instala a chave)
    passphrase: String,
    show_pass: bool,
    versions: String,
    force_version: String,
    num_chunks: String, // quantidade de chunks desejada por .spr
    sprite_cipher: usize, // 0 = aes-ctr, 1 = chacha20
    compress: bool,
    lua_compile: bool,  // compila .lua source -> bytecode (habilita o remap de opcodes)
    luajit: String,     // caminho do luajit.exe (mesmo do client)
    lua_vm_perm: bool,  // Fase 1: LuaJIT patchado do client des-permuta (bytecode stock nunca aparece)
    argon_m: String,
    argon_t: String,
    argon_p: String,

    packer: PathBuf,
    packer_found: bool,
    log: Arc<Mutex<String>>,
    running: Arc<AtomicBool>,
}

impl App {
    fn new() -> Self {
        let packer = locate_packer();
        let packer_found = packer.exists();
        let mut log = String::new();
        if packer_found {
            log.push_str(&format!("[gui] packer: {}\n", packer.display()));
        } else {
            log.push_str("[gui] AVISO: czq-pack.exe nao encontrado ao lado deste app.\n");
        }
        App {
            in_dir: String::new(),
            out_dir: String::new(),
            install_dir: String::new(),
            passphrase: String::new(),
            show_pass: false,
            versions: locate_versions(),
            force_version: String::new(),
            num_chunks: "1024".into(),
            sprite_cipher: 2, // 0=aes-ctr, 1=chacha20, 2=aleatorio por build (padrao)
            compress: true,
            lua_compile: true,
            luajit: locate_luajit(),
            lua_vm_perm: false,
            argon_m: "262144".into(),
            argon_t: "4".into(),
            argon_p: "1".into(),
            packer,
            packer_found,
            log: Arc::new(Mutex::new(log)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    fn append(&self, s: &str) {
        if let Ok(mut l) = self.log.lock() {
            l.push_str(s);
        }
    }

    fn generate_key(&mut self) {
        // 32 bytes aleatórios -> chave/passphrase em base64-url (sem padding).
        let mut buf = [0u8; 32];
        getrandom_fill(&mut buf);
        self.passphrase = b64url(&buf);
        self.show_pass = true;
        self.append("[gui] chave aleatoria gerada. COPIE E GUARDE — sem ela nao da pra reempacotar.\n");
    }

    fn spawn(&self, args: Vec<String>, set_passphrase: bool, install: Option<(String, String)>) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        let log = self.log.clone();
        let running = self.running.clone();
        let packer = self.packer.clone();
        let pass = self.passphrase.clone();
        std::thread::spawn(move || {
            if let Ok(mut l) = log.lock() {
                l.push_str(&format!("\n$ czq-pack {}\n", args.join(" ")));
            }
            let mut cmd = Command::new(&packer);
            cmd.args(&args);
            if set_passphrase {
                cmd.env("CZQ_PASSPHRASE", &pass); // via env: nao vaza na lista de processos
            }
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let result = cmd.output();
            if let Ok(mut l) = log.lock() {
                match result {
                    Ok(out) => {
                        l.push_str(&String::from_utf8_lossy(&out.stdout));
                        l.push_str(&String::from_utf8_lossy(&out.stderr));
                        if out.status.success() {
                            l.push_str("\n[gui] OK - concluido\n");
                            // instala a chave deste build no codigo do client
                            if let Some((out_dir, install_dir)) = &install {
                                let src = std::path::Path::new(out_dir).join("embed").join("czq_build_material.h");
                                let dst = std::path::Path::new(install_dir).join("czq_build_material.h");
                                match std::fs::copy(&src, &dst) {
                                    Ok(_) => l.push_str(&format!("[gui] chave instalada em {}\n[gui] agora e so recompilar o client (WITH_CZQ=1)\n", dst.display())),
                                    Err(e) => l.push_str(&format!("[gui] FALHA ao instalar a chave ({} -> {}): {e}\n", src.display(), dst.display())),
                                }
                            }
                        } else {
                            l.push_str("\n[gui] FALHOU (veja acima)\n");
                        }
                    }
                    Err(e) => l.push_str(&format!("\n[gui] erro ao executar: {e}\n")),
                }
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    fn do_detect(&self) {
        if self.in_dir.trim().is_empty() {
            self.append("[gui] selecione a pasta do client primeiro.\n");
            return;
        }
        // detecta a versao a partir de um .spr dentro da pasta
        let spr = find_first(&self.in_dir, "spr");
        let dat = find_first(&self.in_dir, "dat");
        let Some(spr) = spr else {
            self.append("[gui] nenhum .spr encontrado na pasta para detectar versao.\n");
            return;
        };
        let mut a = vec!["detect".into(), "--spr".into(), spr];
        if let Some(dat) = dat {
            a.push("--dat".into());
            a.push(dat);
        }
        a.push("--versions".into());
        a.push(self.versions.clone());
        if !self.force_version.trim().is_empty() {
            a.push("--force-version".into());
            a.push(self.force_version.trim().into());
        }
        self.spawn(a, false, None);
    }

    fn do_pack(&self) {
        if self.in_dir.trim().is_empty() || self.out_dir.trim().is_empty() || self.passphrase.is_empty() {
            self.append("[gui] pasta do client, pasta de saida e chave sao obrigatorios.\n");
            return;
        }
        let a = vec![
            "packdir".into(),
            "--in".into(),
            self.in_dir.clone(),
            "--out".into(),
            self.out_dir.clone(),
            "--versions".into(),
            self.versions.clone(),
            "--num-chunks".into(),
            {
                let v = self.num_chunks.trim();
                if v.is_empty() { "1024".into() } else { v.to_string() }
            },
            "--sprite-cipher".into(),
            match self.sprite_cipher { 0 => "aes-ctr".into(), 1 => "chacha20".into(), _ => "random".into() },
            "--argon-mcost-kib".into(),
            self.argon_m.trim().into(),
            "--argon-tcost".into(),
            self.argon_t.trim().into(),
            "--argon-pcost".into(),
            self.argon_p.trim().into(),
        ];
        let mut a = a;
        if !self.compress {
            a.push("--no-compress".into());
        }
        if self.lua_compile {
            a.push("--lua-compile".into());
            if !self.luajit.trim().is_empty() {
                a.push("--luajit".into());
                a.push(self.luajit.trim().into());
            }
        }
        if self.lua_vm_perm {
            a.push("--lua-vm-perm".into());
        }
        if !self.force_version.trim().is_empty() {
            a.push("--force-version".into());
            a.push(self.force_version.trim().into());
        }
        let install = if self.install_dir.trim().is_empty() {
            None
        } else {
            Some((self.out_dir.clone(), self.install_dir.clone()))
        };
        self.spawn(a, true, install);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let busy = self.running.load(Ordering::SeqCst);
        if busy {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("hdr").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.heading("CZQ Packer");
            ui.label("Criptografa a pasta inteira do client (varre subpastas). .spr vira chunks/. Cada run rotaciona as chaves.");
            if !self.packer_found {
                ui.colored_label(egui::Color32::from_rgb(220, 120, 0), "czq-pack.exe nao encontrado — veja o log.");
            }
            ui.add_space(6.0);
        });

        egui::TopBottomPanel::bottom("log").resizable(true).min_height(150.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong("Log");
                if ui.button("Limpar").clicked() {
                    if let Ok(mut l) = self.log.lock() {
                        l.clear();
                    }
                }
                if busy {
                    ui.spinner();
                    ui.label("trabalhando…");
                }
            });
            let text = self.log.lock().map(|l| l.clone()).unwrap_or_default();
            egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(9),
                );
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                folder_row(ui, "Pasta do client (entrada) *", &mut self.in_dir);
                folder_row(ui, "Pasta de saida *", &mut self.out_dir);
                ui.small("A saida espelha a arvore: mesmos nomes e subpastas, porem criptografados. Nao pode estar dentro da entrada.");
                folder_row(ui, "Instalar chave em (src/.../czq)", &mut self.install_dir);
                ui.small("Opcional: pasta src\\framework\\core\\czq do client. Ao terminar, o czq_build_material.h e copiado pra la — dai so recompilar.");

                ui.separator();

                // --- chave ---
                ui.horizontal(|ui| {
                    ui.label("Chave (passphrase) *");
                    let te = egui::TextEdit::singleline(&mut self.passphrase)
                        .password(!self.show_pass)
                        .desired_width(320.0);
                    ui.add(te);
                    if ui.button(if self.show_pass { "Ocultar" } else { "Mostrar" }).clicked() {
                        self.show_pass = !self.show_pass;
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("🎲  Gerar chave aleatoria").clicked() {
                        self.generate_key();
                    }
                    if !self.passphrase.is_empty() && ui.button("Copiar").clicked() {
                        ui.output_mut(|o| o.copied_text = self.passphrase.clone());
                        self.append("[gui] chave copiada para a area de transferencia.\n");
                    }
                });
                ui.small("Guarde a chave num lugar seguro. Ela + o build sao necessarios para reempacotar.");

                ui.separator();
                file_row(ui, "versions.xml", &mut self.versions, || pick_file("XML", &["xml"]));
                ui.horizontal(|ui| {
                    ui.label("Cifra de sprite:");
                    egui::ComboBox::from_id_source("cipher")
                        .selected_text(match self.sprite_cipher {
                            0 => "AES-256-CTR (desktop)",
                            1 => "ChaCha20 (mobile/ARM)",
                            _ => "Aleatorio por build (AES/ChaCha)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.sprite_cipher, 2, "Aleatorio por build (AES/ChaCha)");
                            ui.selectable_value(&mut self.sprite_cipher, 0, "AES-256-CTR (desktop)");
                            ui.selectable_value(&mut self.sprite_cipher, 1, "ChaCha20 (mobile/ARM)");
                        });
                    ui.add_space(12.0);
                    ui.label("Qtd. chunks:")
                        .on_hover_text("Quantos arquivos spr_chunk_N.czq gerar por .spr. O packer calcula sprites-por-chunk = total / esta quantidade.");
                    ui.add(egui::TextEdit::singleline(&mut self.num_chunks).desired_width(60.0))
                        .on_hover_text("Ex.: 1024 chunks para ~1.07M sprites ~= 1047 sprites/chunk.");
                    ui.add_space(12.0);
                    ui.label("Forcar versao:");
                    ui.add(egui::TextEdit::singleline(&mut self.force_version).desired_width(70.0));
                    ui.small("(auto se vazio)");
                });
                ui.small("Qtd. chunks: quantos arquivos de chunk gerar (mais chunks = arquivos menores).");
                ui.checkbox(&mut self.compress, "Compactar com zlib antes de cifrar (sprites e arquivos textuais)");

                ui.checkbox(&mut self.lua_compile, "Compilar .lua source -> bytecode antes de cifrar (habilita o remap de opcodes)");
                if self.lua_compile {
                    ui.horizontal(|ui| {
                        ui.label("luajit.exe:");
                        ui.add(egui::TextEdit::singleline(&mut self.luajit).desired_width(360.0))
                            .on_hover_text("Opcional. O packer JA TEM um luajit embutido. So preencha para usar OUTRO LuaJIT (ex.: se voce trocou o do client).");
                        if ui.button("Procurar…").clicked() {
                            if let Some(p) = pick_file("luajit", &["exe"]) {
                                self.luajit = p;
                            }
                        }
                    });
                    if self.luajit.trim().is_empty() {
                        ui.small("Vazio = usa o luajit EMBUTIDO no czq-pack.exe (nao precisa de vcpkg). Preencha so para forcar outro.");
                    }
                    ui.checkbox(&mut self.lua_vm_perm, "Fase 1: LuaJIT do client des-permuta (bytecode stock nunca aparece na RAM)");
                    if self.lua_vm_perm {
                        ui.colored_label(egui::Color32::from_rgb(220, 120, 0),
                            "Requer o LuaJIT do client PATCHADO (veja LUA_VM_PATCH.md). Com LuaJIT stock, os .lua NAO carregam.");
                        ui.small("Gera embed/lj_czq_perm.h. Deixe DESLIGADO ate ter buildado o LuaJIT patchado.");
                    }
                }

                ui.collapsing("Avancado (Argon2id)", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("m_cost (KiB)");
                        ui.add(egui::TextEdit::singleline(&mut self.argon_m).desired_width(90.0));
                        ui.label("t_cost");
                        ui.add(egui::TextEdit::singleline(&mut self.argon_t).desired_width(50.0));
                        ui.label("p_cost");
                        ui.add(egui::TextEdit::singleline(&mut self.argon_p).desired_width(50.0));
                    });
                    ui.small("Padrao 256 MiB / 4 / 1. Reduza so para testes rapidos.");
                });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let can_run = self.packer_found && !busy;
                    if ui.add_enabled(can_run, egui::Button::new("🔒  Criptografar pasta").min_size(egui::vec2(170.0, 34.0))).clicked() {
                        self.do_pack();
                    }
                    if ui.add_enabled(can_run, egui::Button::new("🔎  Detectar versao").min_size(egui::vec2(150.0, 34.0))).clicked() {
                        self.do_detect();
                    }
                    if !self.out_dir.is_empty() && ui.button("Abrir saida").clicked() {
                        open_folder(&self.out_dir);
                    }
                });
                ui.add_space(6.0);
                ui.small("* obrigatorio. A chave e enviada por variavel de ambiente (nao aparece na lista de processos).");
            });
        });
    }
}

// --- helpers de UI ---

fn file_row(ui: &mut egui::Ui, label: &str, value: &mut String, picker: impl Fn() -> Option<String>) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(value).desired_width(360.0));
        if ui.button("Procurar…").clicked() {
            if let Some(p) = picker() {
                *value = p;
            }
        }
    });
}

fn folder_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::TextEdit::singleline(value).desired_width(380.0));
        if ui.button("Procurar…").clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                *value = p.display().to_string();
            }
        }
    });
}

fn pick_file(filter_name: &str, exts: &[&str]) -> Option<String> {
    let mut d = rfd::FileDialog::new();
    if !exts.is_empty() {
        d = d.add_filter(filter_name, exts);
    }
    d.pick_file().map(|p| p.display().to_string())
}

// --- localizar binário / versions.xml ---

fn locate_packer() -> PathBuf {
    let name = if cfg!(windows) { "czq-pack.exe" } else { "czq-pack" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.exists() {
                return p;
            }
        }
    }
    for sub in ["target/release", "target/debug"] {
        let p = PathBuf::from(sub).join(name);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from(name)
}

/// luajit.exe bundled next to this app (copie o do client pra ca — 1 arquivo,
/// standalone, sem precisar de vcpkg). Vazio se nao achar; o packer ainda tenta
/// o vcpkg_installed da pasta de entrada.
fn locate_luajit() -> String {
    let name = if cfg!(windows) { "luajit.exe" } else { "luajit" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.exists() {
                return p.display().to_string();
            }
        }
    }
    String::new()
}

fn locate_versions() -> String {
    let mut candidates: Vec<PathBuf> = vec![PathBuf::from("versions.xml")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("versions.xml"));
            candidates.push(dir.join("../../versions.xml"));
        }
    }
    for c in candidates {
        if c.exists() {
            return c.display().to_string();
        }
    }
    "versions.xml".into()
}

/// Encontra o primeiro arquivo com a extensão dada, recursivamente.
fn find_first(dir: &str, ext: &str) -> Option<String> {
    fn walk(dir: &std::path::Path, ext: &str) -> Option<PathBuf> {
        let rd = std::fs::read_dir(dir).ok()?;
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(found) = walk(&p, ext) {
                    return Some(found);
                }
            } else if p.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case(ext)).unwrap_or(false) {
                return Some(p);
            }
        }
        None
    }
    walk(std::path::Path::new(dir), ext).map(|p| p.display().to_string())
}

fn open_folder(path: &str) {
    #[cfg(windows)]
    let _ = Command::new("explorer").arg(path).spawn();
    #[cfg(not(windows))]
    let _ = Command::new("xdg-open").arg(path).spawn();
}

// --- geração de chave aleatória (sem dependência extra) ---

fn getrandom_fill(buf: &mut [u8]) {
    // Reaproveita a fonte de entropia do SO. rfd/eframe já puxam getrandom via deps,
    // mas para não depender disso usamos a API do SO diretamente.
    #[cfg(windows)]
    {
        // BCryptGenRandom via ntapi seria ideal; sem dep extra, usamos RtlGenRandom
        // exposto como SystemFunction036 em advapi32.
        #[link(name = "advapi32")]
        extern "system" {
            fn SystemFunction036(buf: *mut u8, len: u32) -> u8;
        }
        let ok = unsafe { SystemFunction036(buf.as_mut_ptr(), buf.len() as u32) };
        if ok == 0 {
            // fallback fraco só se a API falhar (não deve acontecer)
            fill_time_based(buf);
        }
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
        fill_time_based(buf);
    }
}

fn fill_time_based(buf: &mut [u8]) {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let mut x = t as u64 ^ 0x9E37_79B9_7F4A_7C15;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}
