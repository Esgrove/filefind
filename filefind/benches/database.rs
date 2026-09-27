//! Criterion benchmarks for indexed file database operations.
//!
//! Uses deterministic in-memory SQLite fixtures and never touches a live index.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use filefind::database::Database;
use filefind::types::{FileEntry, IndexedVolume, VolumeType};

fn database_with_volume() -> (Database, i64) {
    let database = Database::open_in_memory().expect("open benchmark database");
    let volume = IndexedVolume {
        id: None,
        serial_number: "benchmark".into(),
        label: None,
        mount_point: "C:".into(),
        volume_type: VolumeType::Ntfs,
        is_online: true,
        last_scan_time: None,
        last_usn: None,
    };
    let volume_id = database.upsert_volume(&volume).expect("insert volume");
    (database, volume_id)
}

fn entries(volume_id: i64, count: usize, duplicate_percent: usize) -> Vec<FileEntry> {
    (0..count)
        .map(|index| {
            let stem = if index % 100 < duplicate_percent {
                index / 2
            } else {
                index
            };
            let name = format!("project_{stem:08}.{}", if index % 4 == 0 { "jpg" } else { "txt" });
            FileEntry::new(
                volume_id,
                name.clone(),
                format!("C:\\folder_{:03}\\{index:08}_{name}", index % 100),
                false,
            )
        })
        .collect()
}

fn fixture(count: usize, duplicate_percent: usize) -> Database {
    let (mut database, volume_id) = database_with_volume();
    database
        .insert_files_batch(&entries(volume_id, count, duplicate_percent))
        .expect("populate benchmark database");
    database
}

fn sizes() -> Vec<usize> {
    let mut sizes = vec![10_000, 100_000];
    if std::env::var_os("FILEFIND_BENCH_LARGE").is_some() {
        sizes.push(1_000_000);
    }
    sizes
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("database/insert_batch");
    for count in [1_000, 10_000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |bench, &count| {
            bench.iter_batched(
                || {
                    let (database, volume_id) = database_with_volume();
                    (database, entries(volume_id, count, 20))
                },
                |(mut database, files)| {
                    black_box(database.insert_files_batch(black_box(&files)).expect("insert files"));
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("database/search");
    for count in sizes() {
        let database = fixture(count, 20);
        group.bench_function(BenchmarkId::new("name_common", count), |bench| {
            bench.iter(|| {
                black_box(
                    database
                        .search_by_name(black_box("project_"), 100)
                        .expect("search names"),
                )
            });
        });
        group.bench_function(BenchmarkId::new("name_rare", count), |bench| {
            bench.iter(|| {
                black_box(
                    database
                        .search_by_name(black_box("project_00001234"), 100)
                        .expect("search names"),
                )
            });
        });
        group.bench_function(BenchmarkId::new("glob", count), |bench| {
            bench.iter(|| {
                black_box(
                    database
                        .search_by_glob(black_box("project_*.jpg"), 100)
                        .expect("search glob"),
                )
            });
        });
        group.bench_function(BenchmarkId::new("regex", count), |bench| {
            bench.iter(|| {
                black_box(
                    database
                        .search_by_regex(black_box(r"^project_\d{8}\.jpg$"), false, 100)
                        .expect("search regex"),
                )
            });
        });
    }
    group.finish();
}

fn bench_duplicates(c: &mut Criterion) {
    let mut group = c.benchmark_group("database/duplicates");
    for count in sizes() {
        for duplicate_percent in [2, 50] {
            let database = fixture(count, duplicate_percent);
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(
                BenchmarkId::new(format!("{duplicate_percent}_percent"), count),
                |bench| {
                    bench.iter(|| black_box(database.find_duplicates().expect("find duplicates")));
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_insert, bench_search, bench_duplicates);
criterion_main!(benches);
