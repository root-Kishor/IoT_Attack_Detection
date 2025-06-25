# Import necessary libraries
import pandas as pd
import matplotlib.pyplot as plt
from pmdarima import auto_arima
from sklearn.preprocessing import MinMaxScaler

# Load your dataset
df = pd.read_csv('predictions.csv')

# Check the first few rows to understand the data structure
print(df.head())

# Inspect the column names and ensure there is a 'timestamp' or date column
print(df.columns)

# Assuming 'src_bytes' is the traffic volume and 'timestamp' is the datetime column
# If there is no 'timestamp' column, you might need to use a different column
# If you don't have 'timestamp' in your dataset, set 'date' or any other column to index.
# If 'timestamp' exists, this will convert it into datetime format
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# Check for any missing values
print(df.isnull().sum())

# Drop rows with any missing values
df = df.dropna()

# Set 'timestamp' as index
df.set_index('timestamp', inplace=True)

# Visualize the raw traffic data to inspect it
plt.figure(figsize=(10, 6))
plt.plot(df.index, df['src_bytes'], label='Raw Traffic Data')
plt.xlabel('Date')
plt.ylabel('Traffic Volume (src_bytes)')
plt.title('Raw Traffic Data')
plt.show()

# Apply MinMax scaling to normalize the data for better ARIMA performance
scaler = MinMaxScaler()
df['src_bytes_scaled'] = scaler.fit_transform(df[['src_bytes']])

# Plot the scaled traffic data
plt.figure(figsize=(10, 6))
plt.plot(df.index, df['src_bytes_scaled'], label='Scaled Traffic Data', color='orange')
plt.xlabel('Date')
plt.ylabel('Scaled Traffic Volume')
plt.title('Scaled Traffic Data')
plt.show()

# Split the dataset into training and test sets (80% training, 20% testing)
train_size = int(len(df) * 0.8)
train, test = df['src_bytes_scaled'][:train_size], df['src_bytes_scaled'][train_size:]

# Apply auto_arima to find the best model (seasonal=True if there is seasonality in your data)
model = auto_arima(train, seasonal=True, m=12, stepwise=True, trace=True)

# Fit the model on the training data
model.fit(train)

# Forecast the traffic for the test set
forecast = model.predict(n_periods=len(test))

# Reverse the scaling for both the forecasted and true values
forecast_actual = scaler.inverse_transform(forecast.reshape(-1, 1))
test_actual = scaler.inverse_transform(test.values.reshape(-1, 1))

# Plot the results
plt.figure(figsize=(10, 6))
plt.plot(df.index[train_size:], test_actual, label='True Traffic', color='blue')
plt.plot(df.index[train_size:], forecast_actual, label='Predicted Traffic', color='red')
plt.title('Traffic Prediction Using ARIMA')
plt.xlabel('Date')
plt.ylabel('Traffic Volume (src_bytes)')
plt.legend()
plt.show()
