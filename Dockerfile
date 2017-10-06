FROM ruby:2.4-stretch

COPY . /data
WORKDIR /data

ENV LANG      C.UTF-8
ENV LANGUAGE  C.UTF-8
ENV LC_ALL    C.UTF-8

RUN bundle

ENTRYPOINT ["yawast"]
