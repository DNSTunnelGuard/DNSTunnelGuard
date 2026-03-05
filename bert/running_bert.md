# Running BERT

## Installing Dependencies

Set up a virtual environment and install all of the necessary dependencies. A list of modules as well as their necessary versions can be found in requirements.txt. 

---

## Downloading Machine Learning Model

Create a directory called model_weights or something similar. Go to the google drive link in drive_link.txt. In the drive you will find five folders with different machine learning models in them. Download the parameters sub folder from the model you select's folder to the model weights folder. Unzip the file and rename it as you see fit.

## Selecting Your Model

**Model Types**
***Note*:** All models were trained on a tunneling dataset from the canadian government.
- **Default:** Balanced starting point. Training configurations are 5 epochs, batch size 32, learning rate of 2e-5 with mild regularization.
- **Fast:** Optimized for training speed. Training configurations are 2 epochs, larger batch size (64), slightly higher learning rate then the default model. Trades accuracy for speed.
- **High Accuracy:** Model was carefully fine-tuned. 10 epochs, small batch size (16), low learning rate (1e-5) with more warmup steps.
- **Low Memory:** Model was configured to be trained on systems with limited vram. Training configurations are a small batch size (8) with gradient accumulation steps of 4, giving an effective batch size of 32.
- **Regularized:** Model was configured to guard against overfitting. Trained with same configurations
as default but with 10x stronger weight decay (0.1 vs 0.01) and more warmup steps.
- **Two Pass:** Trained on the tunneling dataset from the canadian government and then a generated csv meant to mimic difficult to detect malicious queries. Used the default model's configurations in both training sessions.

**Model Stats**
Each model was tested on 1000 queries on three seperate generated CSV files here are is the average accuracy ((True Postives + True Negatives) / Total Queries) for each model as well as the detection threshold and prediction temperature for the models when they analyzed the queries. (You can tune the temperature when running the main.py file)
- **Default:** 85.6% (temp=3, thresh=0.9)
- **Fast:** 95.9% (temp=1, thresh=0.95)
- **High Accuracy:** 79.2% (temp=1, thresh=0.95)
- **Low Memory:** N/A
- **Regularized:** 87.5% (temp=3, thresh=0.9)
- **Two Pass:** 98.7% (temp=1, thresh=0.92)
***Note*:** Temperature controls how the model is distributed. Higher temperature spreads the
distribution more evenly, scores get "pulled in" toward 0.5, away from the extremes.

---

## Running main.py
Run main.py using the command: ./venv/bin/python3 main.py <model_path> <temperature> <port> [debug] 