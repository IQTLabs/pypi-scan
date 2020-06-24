# Import minimal python 3.8 official image
FROM python:3.8

# Set working directory
WORKDIR /usr/src/app

# Copy over dependency list
COPY requirements.txt ./

# Install dependencies
RUN pip install -r requirements.txt

# Copy over remaining files
COPY . .
