# Django Social Networking API

## Installation Steps

1. **Clone the repository**:
    ```sh
    git clone https://github.com/sruthideveloper/socialnetwork.git
    cd your-repository
    ```

2. **Create and activate a virtual environment**:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Run the migrations**:
    ```sh
    python manage.py migrate
    ```

5. **Create a superuser**:
    ```sh
    python manage.py createsuperuser
    ```

6. **Run the application**:
    ```sh
    python manage.py runserver
    ```

## Docker

1. **Build the Docker image**:
    ```sh
    docker-compose build
    ```

2. **Run the Docker container**:
    ```sh
    docker-compose up
    ```

## API Endpoints

You can find the Postman collection in the repository for testing the API endpoints.
