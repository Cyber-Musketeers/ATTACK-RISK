FROM python:3.12
RUN apt update
RUN apt install pipx -y
RUN apt install pylint python3-mypy black python3-bandit -y
RUN pipx ensurepath
ENV PATH="${PATH}:/root/.local/bin"
RUN pipx install poetry
RUN poetry config virtualenvs.in-project true