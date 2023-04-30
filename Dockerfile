FROM python:3.9.6-alpine3.14


# Create app directory
WORKDIR /journeybackend

# Install app dependencies
COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

# Bundle app source
COPY . .

EXPOSE 5000
CMD [ "flask", "run", "--host", "0.0.0.0", "--port", "5000"]
