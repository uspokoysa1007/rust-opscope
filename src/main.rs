use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction, IntelFormatter,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

// ANSI escape codes for coloring
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const MAGENTA: &str = "\x1b[35m";
const BLUE: &str = "\x1b[34m";
const BRIGHT_BLACK: &str = "\x1b[90m";
const BRIGHT_YELLOW: &str = "\x1b[93m";
const BRIGHT_CYAN: &str = "\x1b[96m";

struct ColorOutput {
    buffer: String,
}

impl ColorOutput {
    fn new() -> Self {
        Self {
            buffer: String::with_capacity(128),
        }
    }
}

impl FormatterOutput for ColorOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        match kind {
            FormatterTextKind::Directive | FormatterTextKind::Keyword => {
                self.buffer.push_str(MAGENTA);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::Prefix | FormatterTextKind::Mnemonic => {
                self.buffer.push_str(BOLD);
                self.buffer.push_str(BRIGHT_YELLOW);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::Register => {
                self.buffer.push_str(GREEN);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::Number => {
                self.buffer.push_str(CYAN);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::LabelAddress => {
                self.buffer.push_str(BOLD);
                self.buffer.push_str(RED);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::FunctionAddress => {
                self.buffer.push_str(BOLD);
                self.buffer.push_str(MAGENTA);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            FormatterTextKind::Decorator | FormatterTextKind::Operator => {
                self.buffer.push_str(BRIGHT_BLACK);
                self.buffer.push_str(text);
                self.buffer.push_str(RESET);
            }
            _ => {
                self.buffer.push_str(text);
            }
        }
    }
}

struct DisasmConfig {
    bitness: u32,
    base_rip: u64,
    show_flow: bool,
    show_stats: bool,
    input_bytes: Vec<u8>,
    source_desc: String,
}

fn parse_hex_string(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex
        .replace("0x", "")
        .replace("\\x", "")
        .replace(',', " ")
        .replace(';', " ");
    
    let mut bytes = Vec::new();
    for token in clean.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        if token.len() % 2 == 0 {
            for i in (0..token.len()).step_by(2) {
                let byte_str = &token[i..i + 2];
                match u8::from_str_radix(byte_str, 16) {
                    Ok(b) => bytes.push(b),
                    Err(_) => return Err(format!("Invalid hex byte: '{}'", byte_str)),
                }
            }
        } else if token.len() == 1 {
            match u8::from_str_radix(token, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => return Err(format!("Invalid hex character: '{}'", token)),
            }
        } else {
            return Err(format!("Invalid hex token length: '{}'", token));
        }
    }
    Ok(bytes)
}

fn print_banner() {
    println!("{}{}╔════════════════════════════════════════════════════════════════════════════╗{}", BOLD, CYAN, RESET);
    println!("{}║   OPSCOPE - x86_64 Opcode Inspector & Stream Disassembler                  ║{}", CYAN, RESET);
    println!("{}║   Offline Binary Analysis • Flow Tracing • Colorized Syntax                ║{}", CYAN, RESET);
    println!("{}{}╚════════════════════════════════════════════════════════════════════════════╝{}\n", BOLD, CYAN, RESET);
}

fn print_help() {
    print_banner();
    println!("{}USAGE:{}", BOLD, RESET);
    println!("    opscope [OPTIONS] <FILE | --hex <HEX_STRING>>\n");
    println!("{}OPTIONS:{}", BOLD, RESET);
    println!("    {}--hex <STR>{}        Disassemble hex string (e.g. \"48 31 c0 48 ff c0 c3\")", GREEN, RESET);
    println!("    {}--rip <ADDR>{}       Set base instruction pointer / RIP (default: 0x10000000 or 0x0)", GREEN, RESET);
    println!("    {}--32 / --64{}        Set architecture bitness (default: 64-bit)", GREEN, RESET);
    println!("    {}--no-flow{}          Disable jump direction indicators (↑ loop / ↓ forward)", GREEN, RESET);
    println!("    {}--no-stats{}         Disable final statistics and register analysis summary", GREEN, RESET);
    println!("    {}--help, -h{}         Show this help information\n", GREEN, RESET);
    println!("{}EXAMPLES:{}", BOLD, RESET);
    println!("    opscope payload.bin");
    println!("    opscope --hex \"48 89 e5 e8 05 00 00 00 eb fe 90 90 c3\"");
    println!("    opscope --rip 0x401000 --hex \"31 c0 ff c0 75 fb c3\"");
    println!("    type shellcode.bin | opscope -\n");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return;
    }

    let mut bitness: u32 = 64;
    let mut base_rip: u64 = 0x10000000;
    let mut show_flow = true;
    let mut show_stats = true;
    let mut hex_input: Option<String> = None;
    let mut file_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--32" => bitness = 32,
            "--64" => bitness = 64,
            "--no-flow" => show_flow = false,
            "--no-stats" => show_stats = false,
            "--rip" => {
                if i + 1 < args.len() {
                    let rip_str = args[i + 1].trim_start_matches("0x").trim_start_matches("0X");
                    match u64::from_str_radix(rip_str, 16) {
                        Ok(addr) => base_rip = addr,
                        Err(_) => {
                            eprintln!("{}Error: Invalid RIP address '{}'{}", RED, args[i + 1], RESET);
                            return;
                        }
                    }
                    i += 1;
                } else {
                    eprintln!("{}Error: Missing value for --rip{}", RED, RESET);
                    return;
                }
            }
            "--hex" => {
                if i + 1 < args.len() {
                    hex_input = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("{}Error: Missing value for --hex{}", RED, RESET);
                    return;
                }
            }
            other => {
                if !other.starts_with('-') || other == "-" {
                    file_path = Some(other.to_string());
                } else {
                    eprintln!("{}Unknown option: '{}'{}", YELLOW, other, RESET);
                    return;
                }
            }
        }
        i += 1;
    }

    let (input_bytes, source_desc) = if let Some(hex_str) = hex_input {
        match parse_hex_string(&hex_str) {
            Ok(bytes) => (bytes, format!("Inline Hex ({} bytes)", hex_str.len())),
            Err(err) => {
                eprintln!("{}Hex Parsing Error: {}{}", RED, err, RESET);
                return;
            }
        }
    } else if let Some(path_str) = file_path {
        if path_str == "-" {
            let mut buffer = Vec::new();
            if let Err(e) = io::stdin().read_to_end(&mut buffer) {
                eprintln!("{}Failed to read stdin: {}{}", RED, e, RESET);
                return;
            }
            (buffer, "Standard Input (stdin)".to_string())
        } else {
            let p = PathBuf::from(&path_str);
            match fs::read(&p) {
                Ok(bytes) => (bytes, format!("File: {}", p.display())),
                Err(e) => {
                    eprintln!("{}Failed to read file '{}': {}{}", RED, p.display(), e, RESET);
                    return;
                }
            }
        }
    } else {
        eprintln!("{}Error: No input specified. Provide a file path or use --hex <hex_string>.{}", RED, RESET);
        return;
    };

    if input_bytes.is_empty() {
        eprintln!("{}Warning: Input stream is empty. Nothing to disassemble.{}", YELLOW, RESET);
        return;
    }

    let config = DisasmConfig {
        bitness,
        base_rip,
        show_flow,
        show_stats,
        input_bytes,
        source_desc,
    };

    run_opscope(config);
}

fn run_opscope(cfg: DisasmConfig) {
    print_banner();
    println!("{}Source:{}    {} ({} bytes)", BRIGHT_CYAN, RESET, cfg.source_desc, cfg.input_bytes.len());
    println!("{}Mode:{}      {}-bit Architecture | Base RIP: 0x{:016X}\n", BRIGHT_CYAN, RESET, cfg.bitness, cfg.base_rip);

    let mut decoder = Decoder::with_ip(cfg.bitness, &cfg.input_bytes, cfg.base_rip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_first_operand_char_index(10);

    // Pre-scan pass: detect jump targets
    let mut jump_targets: HashSet<u64> = HashSet::new();
    let mut instructions: Vec<Instruction> = Vec::new();

    let mut temp_instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut temp_instr);
        if temp_instr.is_invalid() {
            continue;
        }
        instructions.push(temp_instr);
        if temp_instr.is_call_near()
            || temp_instr.is_call_far()
            || temp_instr.is_jmp_near()
            || temp_instr.is_jmp_far()
            || temp_instr.is_jmp_short_or_near()
            || temp_instr.is_jcc_short_or_near()
        {
            let target = temp_instr.near_branch_target();
            if target != 0 {
                jump_targets.insert(target);
            }
        }
    }

    println!("{:<18}  {:<26}  {:<5}  {}", 
        format!("{}{}Address/RIP{}", BOLD, BLUE, RESET),
        format!("{}{}Raw Bytes (Opcode){}", BOLD, BRIGHT_BLACK, RESET),
        format!("{}{}Flow{}", BOLD, MAGENTA, RESET),
        format!("{}{}Assembly Instructions{}", BOLD, YELLOW, RESET)
    );
    println!("{}", "─".repeat(84));

    let mut stats_total_instr = 0usize;
    let mut stats_calls = 0usize;
    let mut stats_jumps = 0usize;
    let mut stats_rets = 0usize;
    let mut stats_prefixes = 0usize;
    let mut mnemonic_freq: HashMap<String, usize> = HashMap::new();

    for instr in &instructions {
        stats_total_instr += 1;
        let ip = instr.ip();
        let len = instr.len();
        
        let mut raw_bytes_str = String::new();
        let slice_offset = (ip.saturating_sub(cfg.base_rip)) as usize;
        if slice_offset + len <= cfg.input_bytes.len() {
            let slice = &cfg.input_bytes[slice_offset..slice_offset + len];
            for b in slice {
                raw_bytes_str.push_str(&format!("{:02x} ", b));
            }
        }

        // Flow indicator
        let flow_marker = if !cfg.show_flow {
            "     ".to_string()
        } else if instr.is_call_near() || instr.is_call_far() {
            stats_calls += 1;
            format!("{}●CALL{}", MAGENTA, RESET)
        } else if instr.is_jcc_short_or_near() {
            stats_jumps += 1;
            let target = instr.near_branch_target();
            if target > ip {
                format!("{}↓ jcc{}", YELLOW, RESET)
            } else {
                format!("{}↑ loop{}", RED, RESET)
            }
        } else if instr.is_jmp_near() || instr.is_jmp_short_or_near() || instr.is_jmp_far() {
            stats_jumps += 1;
            let target = instr.near_branch_target();
            if target > ip {
                format!("{}↓ jmp{}", YELLOW, RESET)
            } else {
                format!("{}↑ loop{}", RED, RESET)
            }
        } else if matches!(instr.mnemonic(), iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Retf) {
            stats_rets += 1;
            format!("{}■ RET{}", BLUE, RESET)
        } else if jump_targets.contains(&ip) {
            format!("{}>LOC<{}", GREEN, RESET)
        } else {
            "     ".to_string()
        };

        if instr.has_lock_prefix() || instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix() {
            stats_prefixes += 1;
        }

        let mut output = ColorOutput::new();
        formatter.format(instr, &mut output);

        let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
        *mnemonic_freq.entry(mnem).or_insert(0) += 1;

        // Print row
        println!(
            "{}{:016X}{}  {:<26}  {:5}  {}",
            CYAN,
            ip,
            RESET,
            raw_bytes_str.trim_end(),
            flow_marker,
            output.buffer
        );
    }

    println!("{}", "─".repeat(84));

    if cfg.show_stats {
        println!("\n{}{}══════════════════════ [ Execution & Flow Summary ] ══════════════════════{}", BOLD, CYAN, RESET);
        println!("  • Total Instructions Decoded : {}{}{}", BOLD, stats_total_instr, RESET);
        println!("  • Branching / Jumps (Jmp/Jcc): {}{}{}", YELLOW, stats_jumps, RESET);
        println!("  • Subroutine Calls (Call)    : {}{}{}", MAGENTA, stats_calls, RESET);
        println!("  • Returns (Ret)              : {}{}{}", BLUE, stats_rets, RESET);
        println!("  • Prefixed Instructions      : {}{}{}", BRIGHT_YELLOW, stats_prefixes, RESET);
        println!("  • Distinct Jump Targets      : {}{}{}", GREEN, jump_targets.len(), RESET);

        let mut top_mnemonics: Vec<(&String, &usize)> = mnemonic_freq.iter().collect();
        top_mnemonics.sort_by(|a, b| b.1.cmp(a.1));

        print!("\n  {}Top Mnemonics:{} ", BOLD, RESET);
        let top_k: Vec<String> = top_mnemonics
            .iter()
            .take(6)
            .map(|(m, count)| format!("{}: {}", m, count))
            .collect();
        println!("{}", top_k.join(" | "));
        println!("{}{}═══════════════════════════════════════════════════════════════════════════{}\n", BOLD, CYAN, RESET);
    }
}
