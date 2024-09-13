# Orizon

**Orizon** è un'applicazione Python progettata per eseguire operazioni asincrone avanzate nel contesto del networking. Utilizza librerie come `aiohttp` e `aiodns` per gestire richieste HTTP asincrone e risoluzioni DNS, offrendo anche funzionalità di logging dettagliato.

## Sommario

- [Requisiti di Sistema](#requisiti-di-sistema)
- [Installazione](#installazione)
- [Configurazione](#configurazione)
- [Utilizzo](#utilizzo)
- [Esempi](#esempi)
- [Logging](#logging)
- [Contributi](#contributi)
- [Licenza](#licenza)

## Requisiti di Sistema

- **Python**: Versione 3.7 o superiore
- **pip**: Versione più recente

## Installazione

1. **Clona il repository** o scarica i file nel tuo sistema locale:

    ```bash
    git clone https://github.com/tuo-username/orizon.git
    cd orizon
    ```

2. **Installa le dipendenze** utilizzando `pip`:

    ```bash
    pip install -r requirements.txt
    ```

## Configurazione

1. **File di Configurazione**:

    Orizon utilizza un file di configurazione per gestire le impostazioni dell'applicazione. Puoi creare un file di configurazione denominato `orizon.ini` nella directory principale. Ecco un esempio di file `orizon.ini`:

    ```ini
    [DEFAULT]
    log_level = DEBUG
    output_directory = ./output
    timeout = 10
    ```

    - `log_level`: Livello di logging (es. DEBUG, INFO, WARNING).
    - `output_directory`: Directory in cui salvare i risultati.
    - `timeout`: Timeout per le operazioni di rete.

## Utilizzo

Esegui il programma dal terminale:

```bash
python orizon1.py [opzioni]
