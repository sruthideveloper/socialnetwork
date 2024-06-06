# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    libssl-dev \
    libffi-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create and set the working directory
RUN mkdir /social_api
WORKDIR /social_api

# Copy the requirements file into the image
COPY requirements.txt /social_api/

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /social_api
COPY . /social_api

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Run manage.py commands to migrate the database (uncomment if needed)
# RUN python manage.py migrate

# Run the application (uncomment if needed)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
