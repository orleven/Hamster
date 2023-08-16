#!/bin/bash

file="lock.txt"

./wait-for-it.sh hamster_mysql:3306
./wait-for-it.sh hamster_redis:6379
./wait-for-it.sh hamster_rabbitmq:5672

if [ -f "$file" ]; then
  echo "restarting process..."
else
  echo "starting process..."
  python3 init.py
  echo 1 > "$file"
fi

ps aux | grep "python manager.py" | awk '{print $2}' | xargs kill -9
nohup python3 manager.py > /dev/null  &
echo "started manager"

ps aux | grep "python support.py" | awk '{print $2}' | xargs kill -9
nohup python3 support.py > /dev/null  &
echo "started support!"

ps aux | grep "python server.py"| awk '{print $2}' | xargs kill -9
nohup python3 server.py > /dev/null  &
echo "started server!"

ps aux | grep "python agent.py" | awk '{print $2}' | xargs kill -9
python3 agent.py
echo "started agent!"

echo "started process!"
