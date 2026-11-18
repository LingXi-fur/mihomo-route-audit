# Mihomo Route Audit

[中文说明](#中文说明) · [Changelog](CHANGELOG.md)

Did a subscription refresh move a rule, disable process matching, or add a fallback node? Mihomo Route Audit compares the running core with a local policy and reports what changed. It only reads the controller and can also run offline with a synthetic snapshot.

## Quick start

Download and extract the source from the release page, then run the following in the project directory. Use Python 3.11 or newer on macOS or Linux; no packages to install.

```sh
python3 mihomo_route_audit.py \
  --policy examples/policy.example.json \
  --snapshot examples/snapshot.example.json
```

Expected output:

```json
{"failures": [], "mode": "snapshot", "rules_checked": 2, "status": "PASS"}
```

## Check a running core

1. Copy `examples/policy.example.json` to `policy.local.json`.
2. Set `group` and `node` to the exact names Mihomo reports, and set `tun` to the expected boolean.
3. List the rules expected at the very top, in order. Use `DOMAIN`, `DOMAIN-SUFFIX`, `PROCESS-PATH`, or `PROCESS-PATH-REGEX`. Copy the payload exactly as Mihomo has it.

```sh
python3 mihomo_route_audit.py \
  --policy policy.local.json \
  --socket /absolute/path/to/mihomo.sock
```

Use the core's existing `external-controller-unix` socket, owned by the account running the command. The tool uses only `GET /configs`, `GET /rules`, and `GET /proxies/<name>`; it has no TCP controller or credential option. Each protected rule needs the boolean `extra.disabled` field. If that field is missing, the audit reports an unknown rule state. The live API has been tested against Mihomo v1.19.33.

The audit checks rule mode, the expected TUN setting, process matching where required, and the rule prefix. It also verifies that the fixed group has exactly one member and selects it, and that the returned member is not a nested group, direct route, or proxy with a configured dialer proxy.

## Read the result

| Exit code | Meaning |
| --- | --- |
| `0` | Every check matched the policy. |
| `1` | At least one check failed or a required rule state was unknown. |
| `2` | An input or the controller could not be read or interpreted. |

A failure such as `{"code":"RULE_DISABLED","position":2}` refers to the second rule in your policy. `RULE_MISMATCH` means the rule at that position differs in type, payload or destination group; also check whether another rule moved ahead of it. `GROUP_MEMBERS_MISMATCH` means the group does not contain exactly the expected member.

## Limits and privacy

The controller requests are separate reads. Audit after a profile refresh has finished. A pass covers what the controller reported; it does not verify public IP, location, DNS, IPv6, application traffic, or service availability. Snapshot mode only evaluates the file it was given.

The report does not echo proxy names, hostnames, socket paths, or controller responses. The tool does not change settings, activate profiles, or restart the core. Keep real policies, subscriptions, profiles, and logs outside version control; the included examples are synthetic.

## Test

```sh
python3 -m unittest discover -s tests -v
```

## 中文说明

这是一个只读的 Mihomo 路由审计工具。Clash 更新订阅后，可以用它检查生效规则有没有被调序、停用或改组，以及固定组是否仍只选中指定节点。它不会修改代理配置。

先用上面的离线示例跑一次；检查本机时，把自己的固定组、节点名、TUN 状态和规则顺序填进 `policy.local.json`，再用 `--socket` 指向现有的 Mihomo Unix 控制套接字。退出码 `0` 表示匹配，`1` 表示检查不通过，`2` 表示输入或控制器不可用。

通过只说明控制器报告的规则符合预期。公网出口、IPv6 和应用实际走的连接需要另外实测。真实策略、订阅和日志请留在本机。
