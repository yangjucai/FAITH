use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex_literal::hex;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Instant;
use sysinfo::{System};
use std::mem;

const CHUNK_SIZE: usize = 16 * 1024; // 16KB
const REFRESH_INTERVAL: usize = 100; // 每100次循环刷新一次

fn main() -> io::Result<()> {
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let iv = hex!("1a1b1c1d1e1f20212223242526272829");

    let input_path = Path::new("assets/278M.mp4");
    let output_path = Path::new("assets/encrypted.bin");
    let decrypted_path = Path::new("assets/decrypted278M.mp4");

    // 获取系统信息
    let mut system = System::new();
    system.refresh_all();

    // 记录开始时间
    let start_time = Instant::now();
    let mut encrypt_counter = 0;
    let mut encrypt_cpu_usages = Vec::new();
    let mut encrypt_memory_usages = Vec::new();
    let mut encrypt_buffer_sizes = Vec::new();
    let mut encrypt_cipher_sizes = Vec::new();

    // 1. 加密文件
    encrypt_file(
        input_path,
        output_path,
        &key,
        &iv,
        &mut system,
        &mut encrypt_counter,
        &mut encrypt_cpu_usages,
        &mut encrypt_memory_usages,
        &mut encrypt_buffer_sizes,
        &mut encrypt_cipher_sizes,
    )?;
    println!("加密完成，密文已保存到 encrypted.bin");

    // 计算加密所用的时间
    let encryption_time = start_time.elapsed();
    println!("加密时间: {:?}", encryption_time);

    // 记录解密开始时间
    let start_time = Instant::now();
    let mut decrypt_counter = 0;
    let mut decrypt_cpu_usages = Vec::new();
    let mut decrypt_memory_usages = Vec::new();
    let mut decrypt_buffer_sizes = Vec::new();
    let mut decrypt_cipher_sizes = Vec::new();

    // 2. 解密文件
    decrypt_file(
        output_path,
        decrypted_path,
        &key,
        &iv,
        &mut system,
        &mut decrypt_counter,
        &mut decrypt_cpu_usages,
        &mut decrypt_memory_usages,
        &mut decrypt_buffer_sizes,
        &mut decrypt_cipher_sizes,
    )?;
    println!("解密完成，内容已保存到 decrypted2.2G.mp4");

    // 计算解密所用的时间
    let decryption_time = start_time.elapsed();
    println!("解密时间: {:?}", decryption_time);

    // 3. 验证解密结果
    if files_equal(input_path, decrypted_path)? {
        println!("解密验证成功！");
    } else {
        println!("解密验证失败！");
    }

    // 打印加密统计信息
    print_statistics("加密", &encrypt_cpu_usages, &encrypt_memory_usages, &encrypt_buffer_sizes, &encrypt_cipher_sizes);

    // 打印解密统计信息
    print_statistics("解密", &decrypt_cpu_usages, &decrypt_memory_usages, &decrypt_buffer_sizes, &decrypt_cipher_sizes);

    Ok(())
}

/// 分块加密文件并监控资源使用情况
fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    iv: &[u8],
    system: &mut System,
    counter: &mut usize,
    cpu_usages: &mut Vec<f32>,
    memory_usages: &mut Vec<u64>,
    buffer_sizes: &mut Vec<usize>,
    cipher_sizes: &mut Vec<usize>,
) -> io::Result<()> {
    let mut input_file = fs::File::open(input_path)?;
    let mut output_file = fs::File::create(output_path)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = input_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // 每次循环都创建新的加密器实例
        let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if bytes_read < CHUNK_SIZE {
            let chunk = &buffer[..bytes_read];
            let ciphertext = cipher.encrypt_vec(chunk);
            output_file.write_all(&ciphertext)?;
        } else {
            let ciphertext = cipher.encrypt_vec(&buffer);
            output_file.write_all(&ciphertext)?;
        }

        *counter += 1;
        if *counter % REFRESH_INTERVAL == 0 {
            system.refresh_all();
            let process = system.process(sysinfo::get_current_pid().unwrap()).unwrap();
            let cpu_usage = process.cpu_usage();
            let memory_usage = process.memory();
            let buffer_size = CHUNK_SIZE / 1024;
            let cipher_size = mem::size_of::<Cbc<Aes128, Pkcs7>>() / 1024;

            cpu_usages.push(cpu_usage);
            memory_usages.push(memory_usage);
            buffer_sizes.push(buffer_size);
            cipher_sizes.push(cipher_size);

            // println!("加密中 CPU 使用率: {:.2}%", cpu_usage);
            // println!("当前内存使用量: {:?} KB", memory_usage);
            // println!("缓冲区大小: {} KB", buffer_size);
            // println!("加密器大小: {} KB", cipher_size);
        }
    }

    Ok(())
}

/// 分块解密文件并监控资源使用情况
fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    iv: &[u8],
    system: &mut System,
    counter: &mut usize,
    cpu_usages: &mut Vec<f32>,
    memory_usages: &mut Vec<u64>,
    buffer_sizes: &mut Vec<usize>,
    cipher_sizes: &mut Vec<usize>,
) -> io::Result<()> {
    let mut input_file = fs::File::open(input_path)?;
    let mut output_file = fs::File::create(output_path)?;

    let mut buffer = vec![0u8; CHUNK_SIZE + 16];

    loop {
        let bytes_read = input_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // 每次循环都创建新的加密器实例
        let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let decrypted = cipher.decrypt_vec(&buffer[..bytes_read])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        output_file.write_all(&decrypted)?;

        *counter += 1;
        if *counter % REFRESH_INTERVAL == 0 {
            system.refresh_all();
            let process = system.process(sysinfo::get_current_pid().unwrap()).unwrap();
            let cpu_usage = process.cpu_usage();
            let memory_usage = process.memory();
            let buffer_size = (CHUNK_SIZE + 16) / 1024;
            let cipher_size = mem::size_of::<Cbc<Aes128, Pkcs7>>() / 1024;

            cpu_usages.push(cpu_usage);
            memory_usages.push(memory_usage);
            buffer_sizes.push(buffer_size);
            cipher_sizes.push(cipher_size);

            // println!("解密中 CPU 使用率: {:.2}%", cpu_usage);
            // println!("当前内存使用量: {:?} KB", memory_usage);
            // println!("缓冲区大小: {} KB", buffer_size);
            // println!("加密器大小: {} KB", cipher_size);
        }
    }

    Ok(())
}

/// 比较两个文件内容是否相同
fn files_equal(path1: &Path, path2: &Path) -> io::Result<bool> {
    let mut file1 = fs::File::open(path1)?;
    let mut file2 = fs::File::open(path2)?;

    let mut buf1 = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    loop {
        let n1 = file1.read(&mut buf1)?;
        let n2 = file2.read(&mut buf2)?;

        if n1 != n2 {
            return Ok(false);
        }
        if n1 == 0 {
            return Ok(true);
        }
        if buf1[..n1] != buf2[..n2] {
            return Ok(false);
        }
    }
}

/// 打印统计信息
fn print_statistics(
    operation: &str,
    cpu_usages: &[f32],
    memory_usages: &[u64],
    buffer_sizes: &[usize],
    cipher_sizes: &[usize],
) {
    if cpu_usages.is_empty() {
        println!("{} 没有收集到 CPU 使用率数据", operation);
        return;
    }

    let cpu_usage_sum: f32 = cpu_usages.iter().sum();
    let cpu_usage_avg = cpu_usage_sum / cpu_usages.len() as f32;
    let cpu_usage_min = cpu_usages.iter().copied().fold(f32::INFINITY, f32::min);
    let cpu_usage_max = cpu_usages.iter().copied().fold(f32::NEG_INFINITY, f32::max);

    let memory_usage_sum: u64 = memory_usages.iter().sum();
    let memory_usage_avg = memory_usage_sum as f64 / memory_usages.len() as f64;
    let memory_usage_min = *memory_usages.iter().min().unwrap();
    let memory_usage_max = *memory_usages.iter().max().unwrap();
    let memory_usage_sum: u64 = memory_usages.iter().sum();

    let buffer_size_sum: usize = buffer_sizes.iter().sum();
    let buffer_size_avg = buffer_size_sum as f64 / buffer_sizes.len() as f64;
    let buffer_size_min = *buffer_sizes.iter().min().unwrap();
    let buffer_size_max = *buffer_sizes.iter().max().unwrap();

    let cipher_size_sum: usize = cipher_sizes.iter().sum();
    let cipher_size_avg = cipher_size_sum as f64 / cipher_sizes.len() as f64;
    let cipher_size_min = *cipher_sizes.iter().min().unwrap();
    let cipher_size_max = *cipher_sizes.iter().max().unwrap();

    // println!("{} 统计信息:", operation);
    // println!("  CPU 使用率 - 平均: {:.2}%, 最小: {:.2}%, 最大: {:.2}%", cpu_usage_avg, cpu_usage_min, cpu_usage_max);
    // println!("  内存使用量 - 平均: {:.2} KB, 最小: {} KB, 最大: {} KB, 总计: {} KB", memory_usage_avg, memory_usage_min, memory_usage_max, memory_usage_sum);
    // println!("  缓冲区大小 - 平均: {:.2} KB, 最小: {} KB, 最大: {} KB", buffer_size_avg, buffer_size_min, buffer_size_max);
    // println!("  加密器大小 - 平均: {:.2} KB, 最小: {} KB, 最大: {} KB", cipher_size_avg, cipher_size_min, cipher_size_max);
}
