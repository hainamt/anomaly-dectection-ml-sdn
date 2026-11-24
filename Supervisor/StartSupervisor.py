import sys
import time
import os
import logging
import pandas as pd
import glob
import re
import joblib
from Attributes import features
from Logger.CustomLogging import CustomFormatter
from Attributes.Labels import PredictLabels
from ManipAPI.Reaction import RESTDBconfig, RESTFWconfig, RESTOFconfig
from MLinitiater.mlinitiater import MLInitiater
from Datapipeline.DataPreprocessor import AttributesRemover, Standardizer, CustomCleaner, PipelineLoader, TransformerMixin, BaseEstimator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSVFILEPATH = os.path.join(BASE_DIR, 'Captures', 'CSV')
DATA_PIPELINE_FILEPATH = os.path.join(BASE_DIR, 'Supervisor', 'Datapipeline', 'pipeline_data_last.joblib')
MODEL_FILEPATH = os.path.join(BASE_DIR, 'Models', 'cls_bag_rf_colab.pkl')
CSV_PATTERN = 'Flow_*.pcap_Flow.csv'
POLL_SECONDS = 1

# Reaction to anomalies: each anomalous flow adds ANOMALY_SCORE to the source's status,
# which decays by SCORE_DECAY_PER_MINUTE (applied whenever a flow from that source is processed). At BLOCK_THRESHOLD the
# source is blocked on its switch for BLOCK_SECONDS.
ANOMALY_SCORE = 30
SCORE_DECAY_PER_MINUTE = 10
BLOCK_THRESHOLD = 100
BLOCK_SECONDS = 1800
columns = features.attrs

# create logger with 'spam_application'
log = logging.getLogger("Supervisor")
log.setLevel(logging.INFO)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

ch.setFormatter(CustomFormatter())

log.addHandler(ch)

def initiateSpvs():
    log.info('Starting Supervisor...')

    try:
        DB = RESTDBconfig()
        log.info('Connected to the database')
    except Exception as ex:
        log.error('Cannot connect to the database (is mongod running?): %s', ex)
        sys.exit(1)
    try:
        OF = RESTOFconfig()
        OF.check_connection()
        log.info('Ready to manipulate with OpenFlow')
    except Exception as ex:
        log.error('Cannot reach the controller REST API (is ryu-manager running with ofctl_rest.py?): %s', ex)
        sys.exit(1)

    idsapp = MLInitiater(MODEL_FILEPATH, DATA_PIPELINE_FILEPATH)

    processed = set()
    decayed_until = {}  # ip -> time up to which its score decay has been applied
    blocked_until = {}  # ip -> time its block rule expires
    while True:
        new_files = set(glob.glob(os.path.join(CSVFILEPATH, CSV_PATTERN))) - processed
        if not new_files:
            time.sleep(POLL_SECONDS)
            continue
        time.sleep(3)  # give CICFlowMeter time to finish writing the CSV

        for csv_file in sorted(new_files, key=os.path.getmtime):
            processed.add(csv_file)
            df = pd.read_csv(csv_file)
            if len(df) == 0:
                continue
            predictions = idsapp.predict(df)
            for i in range(len(df)):
                ip_src = str(df.iloc[i,1])
                if DB.DBconfig_query(ip_src)[0] is None:
                    log.info("Ignored flow from unknown IP: " + ip_src)
                    continue
                if df.index[i] not in predictions.index:
                    log.info("Ignored flow with NaN or infinite features: " + ip_src + " -> " + str(df.iloc[i,3]))
                    continue
                # Apply the decay on every flow, so the stored score goes down over time
                # and not only when the next anomaly arrives
                now = time.time()
                since = decayed_until.setdefault(ip_src, now)
                decay = int((now - since) / 60 * SCORE_DECAY_PER_MINUTE)
                if decay > 0:
                    DB.DBconfig_decrease_status(ip_src, decay)
                    decayed_until[ip_src] = since + decay * 60 / SCORE_DECAY_PER_MINUTE
                if predictions[df.index[i]] == PredictLabels.ANOMALY.value:
                    DB.DBconfig_update_status(ip_src, increase=ANOMALY_SCORE)
                    dp, stt = DB.DBconfig_query(ip_src)
                    log.warning("ANOMALY DETECTED FROM: " + ip_src + " attached with Switch ID: " + str(dp))
                    log.warning('Emergency level: ' + str(stt))
                    if stt >= BLOCK_THRESHOLD and now < blocked_until.get(ip_src, 0):
                        log.info("Source " + ip_src + " is already blocked")
                    elif stt >= BLOCK_THRESHOLD:
                        try:
                            OF.block_entry(dp, ip_src, time=BLOCK_SECONDS)
                            blocked_until[ip_src] = now + BLOCK_SECONDS
                            log.info("Source %s has been blocked for %d minutes, entry priority: 11111", ip_src, BLOCK_SECONDS // 60)
                        except Exception as ex:
                            log.error('Error occurred when adding flow entry', exc_info=True)
                else:
                    log.info("Normal flow: " + ip_src + " -> " + str(df.iloc[i,3]))

if __name__ == "__main__":
    initiateSpvs()
