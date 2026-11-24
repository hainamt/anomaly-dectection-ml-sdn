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
                if predictions[df.index[i]] == PredictLabels.ANOMALY.value:
                    DB.DBconfig_update_status(ip_src,increase=30)
                    dp, stt = DB.DBconfig_query(ip_src)
                    log.warning("ANOMALY DETECTED FROM: " + ip_src + " attached with Switch ID: " + str(dp))
                    log.warning('Emergency level: ' + str(stt))
                    if stt >= 100:
                        try:
                            OF.block_entry(dp, ip_src)
                            log.info("Source " + ip_src + " has been blocked for 30 minutes, entry priority: 11111" ) 
                        except Exception as ex:
                            log.error('Error occurred when adding flow entry', exc_info=True)
                else:
                    log.info("Normal flow: " + ip_src + " -> " + str(df.iloc[i,3]))

if __name__ == "__main__":
    initiateSpvs()
