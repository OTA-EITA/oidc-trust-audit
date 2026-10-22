# oidc-trust-audit

[![ci](https://github.com/OTA-EITA/oidc-trust-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/oidc-trust-audit/actions/workflows/ci.yml)

GitHub Actions や EKS の ServiceAccount から、OIDC でクラウドに入る**信頼関係の設定ミス**を検出する CLI です。
AWS IAM ロールの信頼ポリシーと、Google Cloud の Workload Identity Federation プロバイダを対象にしています。

A CLI that finds over-permissive OIDC federation trust in AWS IAM roles and Google Cloud Workload Identity providers,
such as roles that any GitHub repository can assume.

## なぜ作ったか

アクセスキーを使わない OIDC 連携は安全な方法として広まりましたが、条件の書き方を 1 つ間違えると、**世界中の誰でも**ロールを引き受けられてしまいます。

| よくある設定ミス | 何が起きるか |
|---|---|
| `sub` 条件がない | GitHub 上の**どのリポジトリ**のワークフローからでもロールを使える |
| `repo:my-org*/...` | `my-org-evil` という組織を作った攻撃者も一致する |
| `repo:my-org/app:*` | ブランチを push できる人なら誰でも本番ロールを使える |
| IRSA の `system:serviceaccount:*:x` | namespace を作れる人なら誰でもロールを使える |
| GCP プロバイダの attribute condition が空 | どのリポジトリのトークンでもプールに入れる |

管理画面ではどれも「OIDC で連携済み」に見えるため、目視では気づきにくい問題です。

## 特徴

- **クラウドの認証情報が不要**: AWS CLI / gcloud が出力する JSON を読むだけなので、エクスポートしたデータを CI 上で安全に監査できます。
- **IAM の評価ルールに沿った判定**: `StringLike` だけがワイルドカードを展開する、同じキーの値は OR、演算子どうしは AND、`StringNotLike` は制限にならない、といった IAM の仕様を踏まえて判定します。
- **SARIF 出力**: GitHub の Code scanning に取り込めます。結果は入力ファイル内の該当ロールの行を指します。
- **修正方法つき**: すべての指摘に、具体的な条件の書き方を添えています。

## ルール

| ID | 重大度 | 内容 |
|---|---|---|
| AWS-GHA-001 | HIGH | GitHub OIDC の信頼に `sub` 条件がない |
| AWS-GHA-002 | HIGH | `sub` がどの所有者（組織・ユーザー）でも一致する |
| AWS-GHA-003 | HIGH | `sub` が所有者の前方一致（`repo:my-org*/...`） |
| AWS-GHA-004 | MEDIUM | 所有者の全リポジトリ、またはリポジトリ名の前方一致 |
| AWS-GHA-005 | MEDIUM | どのブランチ・タグ・PR・環境からでも使える |
| AWS-GHA-006 | LOW | ブランチや環境がワイルドカード（保護ルールの確認を推奨） |
| AWS-GHA-007 | LOW | `aud` が `sts.amazonaws.com` に固定されていない |
| AWS-IRSA-001 | HIGH | EKS IRSA の信頼に `sub` 条件がない |
| AWS-IRSA-002 | HIGH | どの namespace の ServiceAccount でも一致する |
| AWS-IRSA-003 | MEDIUM | namespace 内のどの ServiceAccount でも一致する |
| AWS-IRSA-004 | LOW | `aud` が固定されていない |
| AWS-OIDC-001 | HIGH | その他の OIDC プロバイダの信頼に `sub` 条件がない |
| AWS-ROLE-001 | HIGH | 信頼ポリシーが条件なしで `Principal: "*"` を許可 |
| GCP-GHA-001 | HIGH | GitHub 用プロバイダに attribute condition がない |
| GCP-GHA-002 | HIGH | 条件が所有者もリポジトリも固定していない |
| GCP-GHA-003 | HIGH | `startsWith` による所有者の前方一致 |
| GCP-GHA-004 | LOW | 所有者を名前で固定している（`repository_owner_id` を推奨） |
| GCP-GHA-005 | LOW | 条件に `\|\|` があり、各分岐の確認が必要 |
| GCP-OIDC-001 | MEDIUM | その他の OIDC プロバイダに attribute condition がない |

GCP の attribute condition は CEL 式です。完全な評価器ではなくパターンで判定しているため、複雑な式は GCP-GHA-005 で手動確認を促します。

## インストール

[Releases](https://github.com/OTA-EITA/oidc-trust-audit/releases) からバイナリをダウンロードするか、Go でインストールします。

```sh
go install github.com/OTA-EITA/oidc-trust-audit/cmd/oidc-trust-audit@latest
```

## 使い方

```sh
# AWS: アカウントの全ロールを読み取り専用の権限でエクスポートして監査
aws iam get-account-authorization-details --filter Role > roles.json
oidc-trust-audit roles.json

# GCP: プールのプロバイダをエクスポートして監査
gcloud iam workload-identity-pools providers list \
  --location=global --workload-identity-pool=github --format=json > providers.json
oidc-trust-audit providers.json

# 標準入力からも読めます
aws iam get-role --role-name deploy | oidc-trust-audit -

# MEDIUM 以上で終了コード 1、問題のある項目だけ表示
oidc-trust-audit --fail-on medium --quiet roles.json providers.json
```

入力形式（`get-account-authorization-details` / `list-roles` / `get-role` / gcloud の `list` / `describe`）は自動で判別します。

出力例:

```
SEVERITY  RULE          RESOURCE                                                                           MESSAGE
HIGH      AWS-GHA-001   arn:aws:iam::111122223333:role/gha-no-sub                                          any GitHub repository can assume this role (no token.actions.githubusercontent.com:sub condition)
HIGH      AWS-IRSA-002  arn:aws:iam::111122223333:role/irsa-any-namespace                                  sub "system:serviceaccount:*:external-dns" allows any namespace
HIGH      AWS-GHA-003   arn:aws:iam::111122223333:role/gha-prefix                                          sub "repo:example-org*/*" matches any owner starting with that prefix
HIGH      AWS-ROLE-001  arn:aws:iam::111122223333:role/open-to-world                                       trusts Principal "*" with no conditions
HIGH      GCP-GHA-001   projects/123456789/locations/global/workloadIdentityPools/github/providers/open    accepts tokens from every GitHub repository (no attribute condition)
HIGH      GCP-GHA-003   projects/123456789/locations/global/workloadIdentityPools/github/providers/prefix  assertion.repository.startsWith("example-org") also matches other owners
MEDIUM    GCP-OIDC-001  projects/123456789/locations/global/workloadIdentityPools/gitlab/providers/gitlab  provider for https://gitlab.com has no attribute condition
LOW       AWS-IRSA-004  arn:aws:iam::111122223333:role/irsa-any-namespace                                  no aud condition
LOW       AWS-GHA-007   arn:aws:iam::111122223333:role/gha-prefix                                          no token.actions.githubusercontent.com:aud condition

worst=HIGH high=6 medium=1 low=2 pass=2
```

（[`internal/awsiam/testdata`](internal/awsiam/testdata) と [`internal/gcpwif/testdata`](internal/gcpwif/testdata) の、意図的に脆弱にしたサンプルに対する実行結果です）

| フラグ | 既定値 | 説明 |
|---|---|---|
| `--output` | `table` | `table` / `json` / `markdown` / `sarif` |
| `--fail-on` | `high` | この重大度以上の指摘があれば終了コード 1 |
| `--quiet` | `false` | PASS を表示しない |
| `--list` | - | ルール一覧を表示 |

## GitHub Actions で定期監査する

このリポジトリは Composite Action としても使えます。結果は Code scanning に登録され、ジョブのサマリーにも表示されます。

```yaml
name: oidc-trust-audit
on:
  schedule:
    - cron: "0 0 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  id-token: write          # 監査用の読み取り専用ロールを OIDC で引き受ける
  security-events: write   # SARIF のアップロード

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/iam-read-only-audit
          aws-region: ap-northeast-1
      - run: aws iam get-account-authorization-details --filter Role > roles.json
      - uses: OTA-EITA/oidc-trust-audit@v0.1.0
        with:
          files: roles.json
          fail-on: high
```

監査用のロール自体も、このツールで `repo:OWNER/REPO:ref:refs/heads/main` のように固定されていることを確認してください。

## 開発

```sh
make test   # go test -race
make lint   # golangci-lint（gosec を含む）
```

## License

MIT
