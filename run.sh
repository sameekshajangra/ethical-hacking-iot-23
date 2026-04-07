#!/bin/bash
source venv/bin/activate

echo "Generating synthetic IoT-23 dataset..."
python generate_dataset.py

echo "Training the Random Forest model..."
python train_model.py

echo "Starting the Streamlit dashboard..."
streamlit run app.py
