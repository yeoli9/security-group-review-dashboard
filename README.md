# AWS Security Group Review Dashboard

ISMS 보안 검토를 위한 AWS Security Group 시각화 대시보드.

미사용 SG, 과도한 규칙, 순환 참조를 한눈에 파악하여 최소권한원칙을 정립할 수 있습니다.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 주요 기능

- **23개 AWS 리소스 타입 수집** — EC2, RDS, Aurora, ALB/NLB, Lambda, ECS, EKS, ElastiCache, Redshift, OpenSearch, DocumentDB, MSK, EMR, SageMaker, MWAA, DMS, EFS, DAX, Neptune, MemoryDB 등
- **보안 분석** — 미사용 SG, 위험 규칙 (critical/high/medium), 순환 참조, 중복 규칙, default SG 규칙 검토
- **그래프 시각화** — Cytoscape.js 기반 네트워크 그래프, VPC별 경계선 표시
- **테이블 뷰** — 정렬 가능한 SG 목록 테이블 (그래프/테이블 전환)
- **멀티 계정** — `~/.aws/config` 프로파일 자동 감지, 동일 계정 중복 제거
- **필터링** — Profile, VPC, Risk Level, 검색어, 미사용 숨김
- **내보내기** — 미사용 SG 목록 JSON/CSV 다운로드

## 스크린샷

### 그래프 뷰
SG를 노드로, 리소스 연결과 SG 간 참조를 엣지로 시각화합니다.
- 노드 색상: 정상(파랑), 위험(빨강), 주의(노랑), 미사용(회색)
- VPC별 점선 경계로 그룹 구분

### 테이블 뷰
SG 목록을 테이블로 확인하고 컬럼별 정렬이 가능합니다.

## 설치 및 실행

### 사전 요구사항

- Python 3.9+
- AWS CLI 프로파일 설정 (`~/.aws/config` 또는 `~/.aws/credentials`)

### 설치

```bash
git clone https://github.com/yeoli9/security-group-review-dashboard.git
cd security-group-review-dashboard
pip install -r requirements.txt
```

### 실행

```bash
python server.py 5001
```

브라우저에서 http://localhost:5001 접속 후 **Collect** 버튼으로 데이터를 수집합니다.

### 사용 흐름

1. **Collect** 클릭 → AWS 프로파일 선택 → 수집 시작
2. 수집 완료 후 그래프/테이블 뷰에서 SG 현황 확인
3. 필터로 VPC, 위험도, 검색어 기반 필터링
4. SG 노드 또는 테이블 행 클릭 → 상세 패널에서 규칙/리소스 확인
5. 미사용 SG는 JSON/CSV로 내보내기

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
├── collector.py          # AWS 데이터 수집 (23개 리소스 타입)
├── analyzer.py           # SG 분석 (미사용, 위험규칙, 순환참조, 중복규칙)
├── server.py             # Flask API 서버
├── requirements.txt      # Python 의존성
├── static/
│   └── index.html        # 대시보드 프론트엔드 (Cytoscape.js)
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
