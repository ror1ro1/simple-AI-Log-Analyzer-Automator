import os
import sqlite3
import json
from google import genai
from google.genai import types

# Krok 1: Inicjalizacja klienta Gemini API
# Klucz API zostanie pobrany automatycznie ze zmiennej środowiskowej GEMINI_API_KEY
client = genai.Client()

# Krok 2: Przygotowanie lokalnej bazy danych SQL (SQLite)
def setup_database():
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyzed_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            severity TEXT,
            category TEXT,
            description TEXT,
            recommended_action TEXT
        )
    ''')
    conn.commit()
    return conn

# Krok 3: Symulacja surowych logów systemowych (np. z firewalla lub systemu EDR)
raw_logs = [
    "2026-11-02 13:45:12 UTC - ActiveDirectory - Warn - User j.doe failed login 5 times in 2 minutes from IP 192.168.1.105",
    "2026-11-02 13:47:00 UTC - Firewall - Info - Connection established from 10.0.0.4 to 8.8.8.8:443",
    "2026-11-02 13:51:22 UTC - Endpoint Protection - Critical - Mimikatz malware signature detected in memory on workstation IP 192.168.1.22"
]

# Krok 4: Funkcja analizująca log za pomocą Agentic AI (Gemini)
def analyze_log_with_ai(raw_log_text):
    prompt = f"""
    Analyze the following raw system log and extract technical security information.
    Categorize the threat severity (Low, Medium, High, Critical), identify the source IP, 
    provide a brief description of the event, and recommend an immediate incident response action.
    
    Raw log: "{raw_log_text}"
    """
    
    # Definiowanie struktury JSON, jaką model MUSI zwrócić (Structured Outputs)
    class LogAnalysis(types.BaseModel):
        timestamp: str
        source_ip: str
        severity: str
        category: str
        description: str
        recommended_action: str

    # Wywołanie modelu Gemini 2.5 Flash w celu ustrukturyzowania i analizy danych
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=LogAnalysis,
            temperature=0.1
        ),
    )
    
    return json.loads(response.text)

# Krok 5: Główna pętla programu - proces ETL (Extract, Transform, Load)
def main():
    print("Inicjalizacja bazy danych...")
    db_connection = setup_database()
    cursor = db_connection.cursor()
    
    print(f"Rozpoczęcie analizy {len(raw_logs)} logów systemowych...\n")
    
    for log in raw_logs:
        try:
            # Transformacja: AI analizuje i strukturyzuje surowy tekst do JSON
            analysis_result = analyze_log_with_ai(log)
            
            # Ładowanie (Load): Zapis ustrukturyzowanych danych do bazy SQL
            cursor.execute('''
                INSERT INTO analyzed_alerts (timestamp, source_ip, severity, category, description, recommended_action)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                analysis_result['timestamp'],
                analysis_result['source_ip'],
                analysis_result['severity'],
                analysis_result['category'],
                analysis_result['description'],
                analysis_result['recommended_action']
            ))
            
            print(f"[SUKCES] Przeanalizowano log. Status zagrożenia: {analysis_result['severity']}")
            
        except Exception as e:
            print(f"[BŁĄD] Nie udało się przeanalizować logu: {e}")
            
    db_connection.commit()
    db_connection.close()
    print("\nProces ETL zakończony. Dane zostały zapisane w bazie security_logs.db.")

if __name__ == "__main__":
    # Aby uruchomić kod, upewnij się, że ustawiono klucz API:
    # W terminalu: export GEMINI_API_KEY="twój_klucz_api"
    if not os.environ.get("GEMINI_API_KEY"):
        print("Uwaga: Brak ustawionej zmiennej środowiskowej GEMINI_API_KEY. Skrypt może nie zadziałać.")
    main()
