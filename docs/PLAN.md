# Security Group Review Dashboard - 기획서

## 1. 프로젝트 개요

### 배경
- ISMS '2.10.1 보안시스템 운영' 항목에 따라 방화벽 정책 정기 검토 필요
- AWS 콘솔/CLI만으로는 SG 전체를 한눈에 파악하기 어려움
- SG가 어떤 리소스에 attach되어 있는지, 미사용인지, 과도한 규칙인지 일괄 확인 어려움

### 목표
1. **미사용 보안그룹** 식별 및 정리
2. **미사용/중복 규칙** 탐지
3. **과도한 규칙** (0.0.0.0/0, 광범위 포트) 식별
4. **SG 간 참조 관계** 시각화 (순환 참조 포함)
5. **최소권한원칙** 정립을 위한 의사결정 지원

### 대상 환경
- AWS default 프로필 계정
- 향후 멀티 계정 확장 가능

---

## 2. 주요 기능

### 2.1 데이터 수집
| 수집 대상 | AWS API | 비고 |
|-----------|---------|------|
| Security Groups | ec2:DescribeSecurityGroups | 전체 SG 목록 + 규칙 |
| EC2 Instances | ec2:DescribeInstances | SG 사용 리소스 |
| RDS Instances | rds:DescribeDBInstances | DB 보안그룹 |
| ALB/NLB | elbv2:DescribeLoadBalancers | LB 보안그룹 |
| Classic LB | elb:DescribeLoadBalancers | 레거시 LB |
| VPC Endpoints | ec2:DescribeVpcEndpoints | 엔드포인트 SG |
| Lambda Functions | lambda:ListFunctions | VPC 연결 Lambda |
| ECS Services | ecs:ListServices/DescribeServices | awsvpc 모드 |
| ENI (Catch-all) | ec2:DescribeNetworkInterfaces | 위 범주에 안 잡힌 리소스 |
| VPCs | ec2:DescribeVpcs | 필터용 |

### 2.2 분석 기능
- **미사용 SG 탐지**: 리소스가 0개인 SG (default SG 제외)
- **위험 규칙 탐지**:
  - 🔴 Critical: 인터넷 전체 오픈 (0.0.0.0/0 all traffic), 관리 포트 오픈 (22, 3389), DB 포트 오픈
  - 🟠 High: 광범위 포트 레인지 (100개 이상), /8 이하 CIDR
  - 🟡 Medium: 인터넷 오픈 특정 포트
- **순환 참조 탐지**: SG A → B → A 또는 A → B → C → A
- **중복 규칙 탐지**: 상위 규칙에 포함되는 하위 규칙

### 2.3 시각화 (대시보드)
- **네트워크 그래프**: Cytoscape.js 기반
  - SG = 원형 노드 (크기 = 연결 리소스 수)
  - 리소스 = 사각형 노드 (색상 = 리소스 타입)
  - SG 참조 = 파란 실선, 리소스 연결 = 회색 점선
  - 위험도별 색상: 정상(파랑), 위험(빨강), 미사용(회색)
- **필터**: VPC, 검색어, 미사용 숨김
- **상세 패널**: SG 클릭 시 인바운드/아웃바운드 규칙, 연결 리소스, 위험 규칙 표시
- **통계 바**: 전체/사용/미사용 SG 수, 위험 규칙 수, 순환 참조 수

### 2.4 내보내기
- 미사용 SG 목록 JSON/CSV 다운로드

---

## 3. 기술 스택

| 구분 | 기술 | 이유 |
|------|------|------|
| Backend | Python + Flask | 빠른 개발, boto3 연동 |
| AWS SDK | boto3 | 표준 AWS SDK |
| Frontend | HTML + Cytoscape.js | 빌드 없이 단일 HTML, 강력한 그래프 시각화 |
| 그래프 레이아웃 | cose (force-directed) | 자동 배치, 관계 시각화에 적합 |

---

## 4. 아키텍처

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  AWS APIs   │────▶│  collector.py│────▶│  sg_data_    │
│  (boto3)    │     │  (수집)      │     │  cache.json  │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                    ┌──────────────┐             │
                    │  analyzer.py │◀────────────┘
                    │  (분석)      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐     ┌──────────────┐
                    │  server.py   │────▶│  Browser     │
                    │  (Flask API) │     │  (index.html)│
                    └──────────────┘     └──────────────┘
```

### API 엔드포인트
| Method | Path | 설명 |
|--------|------|------|
| POST | /api/collect | AWS 데이터 수집 시작 |
| GET | /api/data | 수집된 전체 데이터 |
| GET | /api/findings | 분석 결과 |
| GET | /api/graph | 그래프 시각화 데이터 (필터 지원) |
| GET | /api/sg/{id} | SG 상세 정보 |
| GET | /api/export/unused | 미사용 SG 내보내기 |

---

## 5. 필요 IAM 권한

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
        "elasticloadbalancing:DescribeLoadBalancers",
        "lambda:ListFunctions",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "sts:GetCallerIdentity"
    ],
    "Resource": "*"
}
```

---

## 6. 로드맵

### Phase 1 (현재) — MVP
- [x] AWS 데이터 수집 (EC2, RDS, LB, VPC Endpoint, Lambda, ECS, ENI)
- [x] 분석 (미사용 SG, 위험 규칙, 순환 참조, 중복 규칙)
- [x] 네트워크 그래프 시각화
- [x] 필터 (VPC, 검색, 미사용 숨김)
- [x] 상세 패널 (규칙, 리소스, 위험 표시)
- [x] 미사용 SG 내보내기

### Phase 2 — 확장
- [ ] 멀티 계정/멀티 리전 지원
- [ ] SG 변경 이력 추적 (CloudTrail 연동)
- [ ] 규칙 자동 추천 (사용 패턴 기반)
- [ ] 정기 스캔 및 리포트 생성 (이메일/Slack)
- [ ] SG 규칙 직접 삭제/수정 기능

### Phase 3 — 고도화
- [ ] 네트워크 Flow Logs 분석과 결합
- [ ] 실제 트래픽 기반 미사용 규칙 정밀 탐지
- [ ] 정책 충돌 탐지 심화
- [ ] ISMS 감사 리포트 자동 생성
