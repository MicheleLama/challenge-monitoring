# Challenge Monitoring Elastic Stack

Script realizzato in **Python3** per fare i controlli base (health check) sui tre componenti principali dello stack **Elastic**:
- Elasticsearch  
- Kibana  
- Logstash  

Lo script esegue un solo controllo alla volta, selezionato con il parametro `--check`, e restituisce un output in formato **Nagios** con i classici codici:
- `0` = OK  
- `1` = WARNING  
- `2` = CRITICAL  
- `3` = UNKNOWN  

In caso di errore di connessione o autenticazione, restituisce automaticamente `UNKNOWN`, come richiesto dalla challenge.

---

### ⚙️ Uso

Esempio di esecuzione:

```bash
python3 check_elastic_stack.py --check elasticsearch --host https://localhost:9200 --user elastic --password changeme --insecure
