# SecScan (defensive)

Кроссплатформенная (Windows/Linux/macOS) CLI-утилита для **защитной** проверки:

- инвентаризация процессов/служб/автозапуска и поиск подозрительных признаков
- пассивное обнаружение устройств в локальной сети (по таблицам соседей/ARP)
- локальные security-checks (без эксплуатации)
- отчёты в JSON + подсветка **критичных** находок

## Установка

Требуется Python 3.10+.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

## Запуск

```bash
python -m secscan --help
python -m secscan processes
python -m secscan ports
python -m secscan processes --ioc ioc-example.json --baseline-in baseline/exec-baseline.json --jsonl-out reports/secscan-findings.jsonl
python -m secscan host
python -m secscan network
python -m secscan report --out report.json --ioc ioc-example.json --baseline-in baseline/exec-baseline.json --jsonl-out reports/secscan-findings.jsonl
```

Проверка скрытых портов и (опционально) завершение подозрительных процессов:

```bash
python -m secscan ports
python -m secscan ports --kill-suspicious
```

`--kill-suspicious` всегда спрашивает подтверждение для каждого процесса (безопасный режим).

## Важно

Эта утилита **не выполняет взлом**, **не эксплуатирует уязвимости** и по умолчанию использует только безопасные/пассивные источники (например, ARP/neighbor cache, локальные настройки).

## Проверка скрытых процессов

- Утилита делает эвристический анализ процессов и на Windows дополнительно сравнивает `psutil` и `tasklist` (best-effort) для выявления аномалий видимости PID.
- Это полезно для обнаружения подозрительных расхождений, но **не является полноценным anti-rootkit** контролем ядра.
- Для корпоративного уровня защиты рекомендуется запускать вместе с EDR/SIEM и системами контроля целостности.

## Корпоративное применение (рекомендации)

- Используйте как слой **быстрого defensive-аудита** endpoint, а не как единственный инструмент SOC.
- Запускайте по расписанию (например, через корпоративный агент), сохраняйте JSON-отчеты в централизованное хранилище и делайте корреляцию в SIEM.
- Для реагирования включите playbook: проверка подписи файла, хеша, parent-child цепочки, сетевой активности процесса и автозапуска.
- В CLI добавлена отдельная таблица подозрительных процессов с полями: `PID`, имя, путь к `exe`, причина и рекомендация.
- Добавлены enterprise-функции:
  - проверка цифровых подписей (Windows Authenticode),
  - IOC-сверка (`sha256`/`names`/`paths`),
  - tamper-проверка целостности через baseline (`--baseline-out` / `--baseline-in`),
  - экспорт JSONL для SIEM (`--jsonl-out`).

## Быстрый гайд (корпоративный запуск)

1. Создайте baseline целостности:

```powershell
.\.venv\Scripts\python -m secscan processes --baseline-out .\baseline\exec-baseline.json
```

2. Запустите регулярную проверку:

```powershell
.\.venv\Scripts\python -m secscan report --ioc .\ioc-example.json --baseline-in .\baseline\exec-baseline.json --out .\reports\secscan-report.json --jsonl-out .\reports\secscan-findings.jsonl
```

3. Отправляйте `.\reports\secscan-findings.jsonl` в SIEM.

Подробный runbook: `docs/CORPORATE_RUNBOOK.md`.

English documentation:
- `README_EN.md`
- `docs/USER_GUIDE_EN.md`
- `docs/ARCHITECTURE_EN.md`

## Интеграции TI + SIEM "из коробки"

Поддерживаются:
- VirusTotal (`--vt-api-key`, `--vt-upload-malicious`)
- MISP (`--misp-url`, `--misp-key`)
- внешний TI feed API (`--ti-feed-url`, `--ti-feed-token`)
- Splunk HEC (`--splunk-hec-url`, `--splunk-hec-token`)
- ELK/Elasticsearch (`--elk-url`, `--elk-api-key`)
- Microsoft Sentinel (`--sentinel-workspace-id`, `--sentinel-shared-key`)

Пример полного запуска:

```powershell
.\.venv\Scripts\python -m secscan report `
  --ioc .\ioc-example.json `
  --ti-feed-url https://ti.company.local/feed `
  --ti-feed-token <TOKEN> `
  --misp-url https://misp.company.local `
  --misp-key <MISP_KEY> `
  --vt-api-key <VT_KEY> `
  --vt-upload-malicious `
  --jsonl-out .\reports\secscan-findings.jsonl `
  --splunk-hec-url https://splunk.company.local:8088/services/collector/event `
  --splunk-hec-token <HEC_TOKEN> `
  --elk-url https://es.company.local:9200 `
  --elk-api-key <ELK_API_KEY> `
  --sentinel-workspace-id <WORKSPACE_ID> `
  --sentinel-shared-key <SENTINEL_KEY> `
  --out .\reports\secscan-report.json
```

## Запуск в 1 клик + общий анализ

Для Windows добавлены 2 скрипта:

- `run_full_scan.bat` / `run_full_scan.ps1` - полный цикл: сканирование + итоговая агрегация.
- `analyze_scan_results.py` - отдельный агрегатор всех отчетов в `reports/`.

Однокликовый запуск:

```bat
run_full_scan.bat
```

macOS/Linux (Debian/Arch):

```bash
chmod +x ./run_full_scan.sh
./run_full_scan.sh
```

После завершения получите:
- `reports/secscan-report.json` - полный отчет сканирования
- `reports/secscan-findings.jsonl` - события для SIEM
- `reports/secscan-summary.json` - обобщенный отчет: все уязвимости, пути к файлам, хеши, IP, маски/паттерны

