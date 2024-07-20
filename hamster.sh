#!/bin/bash

# 检查参数数量
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 name cmd"
    echo "name: manager, server, support, agent, all"
    echo "cmd: restart, start, stop, status"
    exit 1
fi

name=$1
cmd=$2

stop_module(){
    echo "Stopping $1..."
    pids=$( ps aux | grep "[p]ython $1" | awk '{print $2}')
    if [ ! -z "$pids" ]; then
        for pid in $pids; do
            flag=$(ls -la /proc/$pid | grep -i -q 'Hamster')
            if [ $? -eq 0 ]; then
                kill -9 $pid
            fi
        done
    fi
    echo "Stop $1 successfully!"
}

stop_all(){
    stop_module "manager"
    stop_module "support"
    stop_module "server"
    stop_module "agent"
}

status_module(){
    pids=$( ps aux | grep "[p]ython $1" | awk '{print $2}')
    if [ ! -z "$pids" ]; then
        for pid in $pids; do
            flag=$(ls -la /proc/$pid | grep -i -q 'Hamster')
            if [ $? -eq 0 ]; then
                ps p $pid | grep "[p]ython $1"
            fi
        done
    fi
}

status_all(){
    status_module "manager"
    status_module "support"
    status_module "server"
    status_module "agent"
}


start_module(){
    pids=$( ps aux | grep "[p]ython $1" | awk '{print $2}')
    if [ ! -z "$pids" ]; then
        for pid in $pids; do
            flag=$(ls -la /proc/$pid | grep -i -q 'Hamster')
            if [ $? -eq 0 ]; then
                echo "$1 already running!"
                return
            fi
        done
    fi
    module="${1}.py"
    module_log="log/nohup_${1}.out"
    echo "Starting $1..."
    source venv/bin/activate
    nohup python $module >> $module_log  &
    echo "Start $1 successfully!"
}


start_all(){
    start_module "manager"
    start_module "support"
    start_module "server"
    start_module "agent"
}


case $name in
    manager)
        ;;
    server)
        ;;
    support)
        ;;
    agent)
        ;;
    all)
        ;;
    *)
        echo "Unsupported name: $name"
        exit 1
        ;;
esac

case $cmd in
    restart)
        if [ "$name" == "all" ]; then
            stop_all
            start_all
        else
            stop_module $name
            start_module $name
        fi
        ;;
    start)
        if [ "$name" == "all" ]; then
            start_all
        else
            start_module $name
        fi
        ;;
    stop)
        if [ "$name" == "all" ]; then
            stop_all
        else
            stop_module $name
        fi
        ;;
    status)
        if [ "$name" == "all" ]; then
            status_all
        else
            status_module $name
        fi
        ;;
    *)
        echo "Unsupported cmd: $cmd"
        exit 1
        ;;
esac
