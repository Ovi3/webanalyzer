#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import json
import click
import logging
from core import WebAnalyzer


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option('-u', '--url', type=click.STRING, help='Target')
@click.option('-d', '--directory', default=os.path.join(os.getcwd(), "rules"), help="Rules directory, default ./rules")
@click.option('-a', '--aggression', type=click.IntRange(0, 2), default=0, help='Aggression mode, default 0')
@click.option('-U', '--user-agent', type=click.STRING, help='Custom user agent')
@click.option('-H', '--header', multiple=True, help='Pass custom header LINE to serve')
@click.option('-v', '--verbose', type=click.IntRange(0, 5), default=2, help='Verbose level, default 2')
@click.option('-r', '--rule', type=click.STRING, help="Specify rule")
@click.option('--disallow-redirect', is_flag=True, default=False, help='Disallow redirect')
@click.option('--list-rules', is_flag=True, default=False, help='List rules')
@click.option('--update', is_flag=True, default=False, help="Update rules")
def main(url, update, directory, aggression, user_agent, header, disallow_redirect, list_rules, verbose, rule):
    w = WebAnalyzer()
    w.rule_dir = directory

    if update:
        if w.update_rules():
            click.echo("update rules done")
        return

    if list_rules:
        if not os.path.isdir(directory):
            click.echo("rules directory is not exist, use -d to specify rule directory")
            return

        rules_count = w.reload_rules()
        for i in w.list_rules().values():
            if i.get('desc'):
                click.echo('%s - %s - %s' % (i['name'], i['origin'], i['desc']))
            else:
                click.echo('%s - %s' % (i['name'], i['origin']))

        click.echo("\n%d rules totally" % rules_count)
        return

    if not url:
        click.echo("invalid url, use -u to specify target")
        return

    if aggression:
        w.aggression = aggression

    if user_agent:
        w.headers['user-agent'] = user_agent

    if header:
        for i in header:
            if ':' not in i:
                continue

            key, value = i.split(':', 1)
            w.headers[key] = value

    if disallow_redirect:
        w.allow_redirect = not disallow_redirect

    logging.basicConfig(format='%(asctime)s - %(filename)s - %(levelname)s - %(message)s', level=(5 - verbose) * 10)

    if rule:
        r = w.test_rule(url, rule)
        if r:
            click.echo(json.dumps(r, indent=4))
        return

    if not os.path.isdir(directory):
        click.echo("rules directory is not exist, use -d to specify rule directory")
        return

    r = w.start(url)
    if r:
        click.echo(json.dumps(r, indent=4))


if __name__ == "__main__":
    main()
