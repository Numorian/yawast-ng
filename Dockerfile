FROM python:3.12-bullseye

RUN apt-get update && apt-get install -y \
	apt-transport-https \
	ca-certificates \
	curl \
	wget \
	gnupg \
	unzip \
    --no-install-recommends \
	&& curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
	&& echo "deb https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
	&& apt-get update && apt-get install -y google-chrome-stable \
    fontconfig \
    fonts-ipafont-gothic \
    fonts-wqy-zenhei \
    fonts-thai-tlwg \
    fonts-kacst \
    fonts-noto \
    ttf-freefont \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . /data
WORKDIR /data

ENV LANG      C.UTF-8
ENV LANGUAGE  C.UTF-8
ENV LC_ALL    C.UTF-8

RUN pip install -r requirements.txt

RUN cd /data/ && python -m unittest discover

ENTRYPOINT ["/data/bin/yawast-ng"]
