# Anomaly model

## Training

`python scripts/train_model.py` trains a scikit-learn `IsolationForest` from 2,000 deterministic synthetic normal records by default. `--dataset path.csv` can supply up to one million authorized records with `event_type` and optional normalized fields. The pipeline validates that engineered values are finite and trains only on selected numeric features, not raw free-form text.

Artifacts are:

- `app/ml/models/artifacts/isolation_forest.joblib`: fitted estimator
- `app/ml/models/artifacts/metadata.json`: model/feature/dataset versions and smoke metrics
- `model_versions` relational table: version metadata and artifact path

Artifacts are not committed. Treat trained models as deployment inputs and retrain through a reviewed process.

## Features

UTC hour, weekend indicator, source and destination ports, authentication failure/success indicators, network and privilege event indicators, high severity flag, and bounded message length. Feature schema version is `1`; the service refuses a metadata version mismatch rather than silently applying an incompatible model.

The anomaly score is a normalized transformation of Isolation Forest's decision function. It is a ranking signal, not a calibrated probability. Scores at or above the configured alert threshold produce advisory ML signals; deterministic rules continue if the model is missing. The synthetic probe evaluation is only a pipeline smoke test and is not representative of real SOC efficacy.

## Use and limitations

Validate training-data rights, data quality, and environment representativeness. Tune alert thresholds and baselines against a labeled/analyst-reviewed dataset before operational use. The project does not claim perfect detection or use a supervised classifier without labeled data.

