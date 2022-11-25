#!/bin/bash

echo "restarting process..."
source venv/bin/activate

ps aux | grep "python manager.py" | awk '{print $2}' | xargs kill -9
nohup python manager.py >> log/nohup_manager.out  &
echo "restarted manager"

ps aux | grep "python support.py" | awk '{print $2}' | xargs kill -9
nohup python support.py >> log/nohup_support.out  &
echo "restarted support!"

ps aux | grep "python agent.py" | awk '{print $2}' | xargs kill -9
nohup python agent.py >> log/nohup_agent.out  &
echo "restarted agent!"

ps aux | grep "python server.py"| awk '{print $2}' | xargs kill -9
nohup python server.py >> log/nohup_server.out  &
echo "restarted server!"

echo "restarted process!"
