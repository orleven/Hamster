# 使用Python 3.10的官方基础映像
FROM python:3.10

# 设置工作目录
WORKDIR /app/Hamster/

# 将当前目录中的所有文件复制到容器中的工作目录
COPY . /app/Hamster/
RUN rm -fr /app/Hamster/conf
RUN rm -fr /app/Hamster/venv
RUN rm -fr /app/Hamster/restart.sh
COPY docker/conf /app/Hamster/conf
COPY docker/restart.sh /app/Hamster/restart.sh
COPY docker/wait-for-it.sh /app/Hamster/wait-for-it.sh
RUN chmod +x /app/Hamster/restart.sh
RUN chmod +x /app/Hamster/wait-for-it.sh

## 安装项目依赖
RUN pip3 install -r requirements.txt

# 运行应用程序
ENTRYPOINT ["/bin/bash"]
CMD ["./restart.sh"]

EXPOSE 8000
EXPOSE 8001
EXPOSE 8002
