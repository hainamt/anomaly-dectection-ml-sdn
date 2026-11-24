import joblib
import pandas as pd
from Datapipeline.DataPreprocessor import PipelineLoader

class MLInitiater(object):
    def __init__(self, model_file, data_pipeline_file):
        self.model=joblib.load(model_file)
        self.ppl = PipelineLoader(data_pipeline_file).getPipeline()

    def predict(self, data):
        """Predict every flow in `data` at once.

        Returns a Series indexed like `data`. The pipeline's cleaner drops rows with
        NaN or infinite values (e.g. Flow Byts/s when the duration is 0), so those
        rows are missing from the result.
        """
        cleaned = self.ppl[:-1].transform(data)
        if len(cleaned) == 0:
            return pd.Series(dtype=float)
        return pd.Series(self.model.predict(self.ppl[-1].transform(cleaned)), index=cleaned.index)
