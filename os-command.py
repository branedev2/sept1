#!/usr/bin/env python3
# Test cases for OS command injection via various vectors

#######################################################################
# IMPORTS
#######################################################################
# Airflow imports
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator
from airflow.operators.bash_operator import BashOperator as LegacyBashOperator
from airflow.operators.python_operator import PythonOperator as LegacyPythonOperator
from airflow.utils.dates import days_ago

# Ansible imports
import os
import json
import yaml
from ansible.module_utils.common.collections import ImmutableDict
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase
from ansible import context
import ansible.constants as C

# Asyncio imports
import asyncio
import shlex

# Docker imports
import docker

# Dynamic module imports
import importlib
import importlib.util
import sys

# Environment and subprocess imports
import subprocess
import os

# Fabric imports
import fabric
from fabric import Connection
from fabric.api import run, local, env, sudo
from fabric.tasks import execute

# Logging imports
import logging
import logging.config

# Web framework imports
from flask import Flask, request
import html
import re

app = Flask(__name__)

# Simple callback for Ansible output
class ResultCallback(CallbackBase):
    def __init__(self):
        super(ResultCallback, self).__init__()
        self.host_ok = {}
        self.host_unreachable = {}
        self.host_failed = {}

    def v2_runner_on_ok(self, result):
        self.host_ok[result._host.get_name()] = result._result

    def v2_runner_on_unreachable(self, result):
        self.host_unreachable[result._host.get_name()] = result._result

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.host_failed[result._host.get_name()] = result._result

#######################################################################
# TRUE POSITIVE EXAMPLES (VULNERABLE/INSECURE CODE)
#######################################################################

def bad_case_1():
    command = request.args.get('command', 'ls -la')

    # Dangerous: using user input directly in BashOperator
    dag = DAG('vulnerable_dag_1', description='Vulnerable DAG 1',
              schedule_interval='0 12 * * *',
              start_date=days_ago(1))

    # ruleid: python-os-command-injection-ide
    bash_task = BashOperator(
        task_id='vulnerable_bash_task',
        bash_command=command,
        dag=dag
    )

    return "DAG created with user command"

def bad_case_2():
    command = request.headers.get('X-Command', 'ls -la')

    # Dangerous: using user input directly in legacy BashOperator
    dag = DAG('vulnerable_dag_3', description='Vulnerable DAG 3',
              schedule_interval='0 12 * * *',
              start_date=days_ago(1))
    # ruleid: python-os-command-injection-ide
    bash_task = LegacyBashOperator(
        task_id='vulnerable_legacy_bash_task',
        bash_command=command,
        dag=dag
    )

    return "DAG created with user command in legacy operator"

def bad_case_3():
    command_template = request.json.get('command_template', 'echo "{{ params.value }}"')
    param_value = request.json.get('param_value', 'test')

    # Dangerous: using user input in template and parameters
    dag = DAG('vulnerable_dag_4', description='Vulnerable DAG 4',
              schedule_interval='0 12 * * *',
              start_date=days_ago(1))
    # ruleid: python-os-command-injection-ide
    bash_task = BashOperator(
        task_id='vulnerable_template_task',
        bash_command=command_template,
        params={'value': param_value},
        dag=dag
    )

    return "DAG created with user command template"

def bad_case_4():
    def dynamic_task_generator():
        commands = request.args.getlist('commands')

        dag = DAG('vulnerable_dag_5', description='Vulnerable DAG 5',
                  schedule_interval='0 12 * * *',
                  start_date=days_ago(1))

        tasks = []
        for i, command in enumerate(commands):
            # ruleid: python-os-command-injection-ide
            task = BashOperator(
                task_id=f'dynamic_task_{i}',
                bash_command=command,
                dag=dag
            )
            tasks.append(task)

        # Set task dependencies
        for i in range(1, len(tasks)):
            tasks[i-1] >> tasks[i]

        return dag

    dag = dynamic_task_generator()

    return "Dynamic DAG created with user commands"

def bad_case_5():
    host = request.args.get('host', 'localhost')
    command = request.args.get('command', 'ls -la')

    # Dangerous: using user input directly in Ansible command
    context.CLIARGS = ImmutableDict(connection='local', module_path=['/usr/share/ansible'], forks=10, become=None,
                                    become_method=None, become_user=None, check=False, diff=False)

    loader = DataLoader()
    results_callback = ResultCallback()

    inventory = InventoryManager(loader=loader, sources=f"{host},")
    variable_manager = VariableManager(loader=loader, inventory=inventory)

    play_source = dict(
        name="Ansible Play",
        hosts=host,
        gather_facts='no',
        tasks=[
            # ruleid: python-os-command-injection-ide
            dict(action=dict(module='shell', args=command), register='shell_out')
        ]
    )

    play = Play().load(play_source, variable_manager=variable_manager, loader=loader)

    tqm = None
    try:
        tqm = TaskQueueManager(
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            passwords=dict(),
            stdout_callback=results_callback
        )
        # ruleid: python-os-command-injection-ide
        result = tqm.run(play)
    finally:
        if tqm is not None:
            tqm.cleanup()

    return f"Ansible results: {results_callback.host_ok}"