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
csvfilename= ''
columns = features.attrs
fileindex = 1
undetected = 1

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

    global csvfilename
    global fileindex
    global undetected

    idsapp = MLInitiater(MODEL_FILEPATH, DATA_PIPELINE_FILEPATH)

    while True:
        undetected = 1
        #print("Finding the "+ str(fileindex) + "th flow subset...")
        while undetected:
            file_pointer = "Flow_" + f"{fileindex:05d}" + "*" + ".pcap_Flow.csv"
            files = glob.glob(os.path.join(CSVFILEPATH, file_pointer))
            if len(files) != 0:
                undetected = 0
                #print("Flow subset %sth - %s has been detected!" % (fileindex, files[0]))
                time.sleep(3)

        df = pd.read_csv(str(files[0]))
        fileindex += 1
        if(len(df)==0):
            #print('Empty')
            continue        
        #print("Reading flow...")
        for i in range(len(df)):
            ip_src = str(df.iloc[i,1])
            if DB.db["Topology"].count_documents({"Hosts.IP": ip_src}) == 0:
                log.info("Ignored flow from unknown IP: " + ip_src)
                continue
            if idsapp.predict(df.iloc[[i]])[0] == PredictLabels.ANOMALY.value:
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
