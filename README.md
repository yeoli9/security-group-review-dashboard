# AWS Security Group Review Dashboard

ISMS 보안 검토를 위한 AWS Security Group 시각화 대시보드.

미사용 SG, 과도한 규칙, 순환 참조를 한눈에 파악하여 최소권한원칙을 정립할 수 있습니다.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**한국어** | [English](README_EN.md)

## 주요 기능

- **23개 AWS 리소스 타입 수집** — EC2, RDS, Aurora, ALB/NLB, Lambda, ECS, EKS, ElastiCache, Redshift, OpenSearch, DocumentDB, MSK, EMR, SageMaker, MWAA, DMS, EFS, DAX, Neptune, MemoryDB 등
- **보안 분석** — 미사용 SG, 위험 규칙 (critical/high/medium), 순환 참조, 중복 규칙, default SG 규칙 검토
- **그래프 시각화** — Cytoscape.js 기반 네트워크 그래프, VPC별 경계선 표시
- **테이블 뷰** — 정렬 가능한 SG 목록 테이블 (그래프/테이블 전환)
- **멀티 계정** — `~/.aws/config` 프로파일 자동 감지, 동일 계정 중복 제거
- **필터링** — Profile, VPC, Risk Level, 검색어, 미사용 숨김
- **거버넌스 점검** — 태그 기반 ISMS 거버넌스 (담당자, 검토일, 만료일, 사유 등)
- **내보내기** — 미사용 SG 목록 JSON/CSV 다운로드

## 스크린샷

### 그래프 뷰

SG를 노드로, 리소스 연결과 SG 간 참조를 엣지로 시각화합니다.
- 노드 색상: 정상(파랑), 위험(빨강), 주의(노랑), 미사용(회색)
- VPC별 점선 경계로 그룹 구분

![Graph View](docs/images/graph-view.png)

---

## 퀵스타트

### 사전 요구사항

- AWS CLI 프로파일 설정 (`~/.aws/config` 또는 `~/.aws/credentials`)
- 필요 IAM 권한: [아래 참조](#필요-iam-권한)

### 실행

```bash
git clone https://github.com/yeoli9/security-group-review-dashboard.git
cd security-group-review-dashboard

./run.sh
```

인터랙티브 메뉴에서 화살표 키로 실행 방법을 선택합니다.

```
  AWS Security Group Review Dashboard
  ────────────────────────────────────────

   > Local Setup + Run   Python venv 세팅 후 서버 실행
     Local Run            이미 세팅된 venv로 서버 실행
     Docker Compose       Docker로 빌드 + 실행
     Docker Compose Down  Docker 컨테이너 종료
     Clean                venv, 캐시 등 전부 삭제

  ↑↓ 선택  Enter 실행  q 종료
```

http://localhost:5000 접속 후 **Collect** 버튼으로 데이터를 수집합니다.

---

## 사용 흐름

1. **Collect** 클릭 → AWS 프로파일 선택 → 수집 시작
2. 수집 완료 후 그래프/테이블 뷰에서 SG 현황 확인
3. 필터로 VPC, 위험도, 검색어 기반 필터링
4. SG 노드 또는 테이블 행 클릭 → 상세 패널에서 규칙/리소스 확인
5. 미사용 SG는 JSON/CSV로 내보내기

## 거버넌스 태그 설정

ISMS 점검을 위해 SG에 부착된 AWS 태그를 기반으로 거버넌스 준수 여부를 검사합니다.

`config.json`에서 태그 이름과 규칙을 설정합니다. (`./run.sh` → Configure 메뉴로도 편집 가능)

```json
{
  "governance_tags": {
    "owner": "Owner",
    "project": "Project",
    "environment": "Environment",
    "reviewed_at": "ReviewedAt",
    "expires_at": "ExpiresAt",
    "justification": "Justification",
    "risk_accepted": "RiskAccepted",
    "approved_by": "ApprovedBy"
  },
  "governance_rules": {
    "required_tags": ["owner", "justification"],
    "review_interval_days": 90,
    "warn_expiry_days_before": 14
  }
}
```

| 키 | 기본 태그명 | 설명 |
|----|------------|------|
| `owner` | `Owner` | 담당자/팀 |
| `project` | `Project` | 프로젝트/서비스명 |
| `environment` | `Environment` | prod/staging/dev |
| `reviewed_at` | `ReviewedAt` | 마지막 검토일 (YYYY-MM-DD) |
| `expires_at` | `ExpiresAt` | 만료일 (YYYY-MM-DD) |
| `justification` | `Justification` | SG 존재 사유 |
| `risk_accepted` | `RiskAccepted` | 리스크 수용 여부 |
| `approved_by` | `ApprovedBy` | 승인자 |

환경변수로 태그 이름을 오버라이드할 수 있습니다:

```bash
SG_TAG_OWNER=ResourceOwner SG_TAG_REVIEWED_AT=LastAuditDate python server.py
```

### 검사 항목

- **필수 태그 누락** — `required_tags`에 지정된 태그가 SG에 없으면 경고
- **검토 기한 초과** — `ReviewedAt` 태그 기준 `review_interval_days`일 초과 시 경고
- **만료/만료 임박** — `ExpiresAt` 태그 기준 만료 또는 `warn_expiry_days_before`일 이내 시 경고

## 필요 IAM 권한

Read-only 권한만 사용합니다. (Write API 없음)

```json
{
    "Effect": "Allow",
    "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcEndpoints",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "elasticloadbalancing:DescribeLoadBalancers",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "elasticache:DescribeCacheClusters",
        "redshift:DescribeClusters",
        "es:DescribeDomains",
        "es:ListDomainNames",
        "kafka:ListClustersV2",
        "elasticmapreduce:ListClusters",
        "elasticmapreduce:DescribeCluster",
        "sagemaker:ListNotebookInstances",
        "sagemaker:DescribeNotebookInstance",
        "airflow:ListEnvironments",
        "airflow:GetEnvironment",
        "dms:DescribeReplicationInstances",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticfilesystem:DescribeFileSystems",
        "dax:DescribeClusters",
        "neptune:DescribeDBClusters",
        "memorydb:DescribeClusters",
        "sts:GetCallerIdentity"
    ],
    "Resource": "*"
}
```

## 프로젝트 구조

```
├── app/
│   ├── server.py         # Flask API 서버
│   ├── collector.py      # AWS 데이터 수집 (23개 리소스 타입)
│   ├── analyzer.py       # SG 분석 (미사용, 위험규칙, 순환참조, 거버넌스)
│   ├── governance.py     # 거버넌스 태그 설정 로더
│   └── static/
│       └── index.html    # 대시보드 프론트엔드 (Cytoscape.js)
├── config.json           # 거버넌스 태그/규칙 설정
├── requirements.txt      # Python 의존성
├── run.sh                # 인터랙티브 실행 스크립트
├── Dockerfile            # Docker 이미지 빌드
├── docker-compose.yml    # Docker Compose 설정
└── docs/
    ├── PLAN.md           # 기획서
    └── PROGRESS.md       # 진행 내역
```

## API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/profiles` | AWS 프로파일 목록 |
| POST | `/api/collect` | 데이터 수집 시작 |
| GET | `/api/accounts` | 수집된 계정 목록 |
| GET | `/api/data` | 수집 데이터 |
| GET | `/api/findings` | 분석 결과 |
| GET | `/api/graph` | 그래프 시각화 데이터 |
| GET | `/api/sg/{id}` | SG 상세 정보 |
| GET | `/api/export/unused` | 미사용 SG 내보내기 (JSON/CSV) |

## Contributing

기여를 환영합니다! Issue 또는 Pull Request를 자유롭게 제출해 주세요.

1. Fork 후 새 브랜치 생성 (`git checkout -b feature/my-feature`)
2. 변경사항 커밋 (`git commit -m 'Add my feature'`)
3. 브랜치 푸시 (`git push origin feature/my-feature`)
4. Pull Request 생성

## License

[MIT License](LICENSE)
