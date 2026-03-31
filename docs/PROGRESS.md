# Security Group Review Dashboard - 진행 내역

## 2026-03-31 — 프로젝트 초기 구축

### 완료 항목

#### 1. 프로젝트 구조 생성
```
security-group-review-dashboard/
├── collector.py          # AWS 데이터 수집
├── analyzer.py           # SG 분석 (미사용, 위험규칙, 순환참조)
├── server.py             # Flask API 서버
├── requirements.txt      # 의존성
├── static/
│   └── index.html        # 대시보드 프론트엔드
└── docs/
    ├── PLAN.md           # 기획서
    └── PROGRESS.md       # 진행내역 (이 문서)
```

#### 2. Backend — collector.py
- AWS 보안그룹 전체 수집 (`describe_security_groups`)
- 리소스별 SG 사용 현황 수집:
  - EC2 Instances
  - RDS Instances
  - ALB/NLB (elbv2)
  - Classic LB
  - VPC Endpoints
  - Lambda Functions (VPC 연결)
  - ECS Services (awsvpc 모드)
  - ENI (catch-all — 위 범주에 안 잡힌 리소스)
- VPC 정보 수집 (필터용)
- SG-리소스 매핑 구축
- SG 간 참조 관계 추출

#### 3. Backend — analyzer.py
- **미사용 SG 탐지**: 리소스 0개 + default SG 제외
- **위험 규칙 탐지**:
  - Critical: 0.0.0.0/0 all traffic, 관리포트(22/3389), DB포트
  - High: 100개 이상 포트 레인지, /8 이하 CIDR
  - Medium: 인터넷 오픈 특정 포트
- **순환 참조 탐지**: DFS 기반 cycle detection (depth 5 제한)
- **중복 규칙 탐지**: subset 관계 확인
- **요약 통계**: 전체/사용/미사용 SG, 규칙 수, VPC별 분포

#### 4. Backend — server.py
- Flask 기반 API 서버
- 엔드포인트: collect, data, findings, graph, sg detail, export
- 수집 결과 JSON 파일 캐싱
- 그래프 데이터 필터링 (VPC, 검색어, 미사용 숨김)

#### 5. Frontend — index.html
- 다크 테마 UI (GitHub 스타일)
- Cytoscape.js 네트워크 그래프
  - SG 노드: 원형, 크기=리소스 수, 색상=위험도
  - 리소스 노드: 사각형, 색상=타입별 (EC2=주황, RDS=초록, LB=보라, VPCEndpoint=노랑, Lambda/ECS=하늘)
  - SG 참조 엣지: 파랑 실선 + 화살표
  - 리소스 연결: 회색 점선
- 필터 바: VPC, 검색어, 미사용 숨김 체크박스
- 통계 바: Total/Used/Unused/Risky/Circular 카운트
- 상세 패널: SG 클릭 시 규칙/리소스/위험 정보 표시
- 인터렉션: 호버 툴팁, 클릭 시 이웃 노드 하이라이트
- 내보내기: 미사용 SG JSON/CSV 다운로드

## 2026-03-31 — 수집 대상 확장 (15개 서비스 추가)

### 추가된 수집 대상

#### 높은 우선순위 (6개)
| 서비스 | API | 비고 |
|--------|-----|------|
| RDS Aurora Clusters | `rds.describe_db_clusters()` | 클러스터 레벨 SG (인스턴스와 별도) |
| ElastiCache | `elasticache.describe_cache_clusters()` | Redis/Memcached |
| Redshift | `redshift.describe_clusters()` | 데이터웨어하우스 |
| OpenSearch | `opensearch.describe_domains()` | VPC 모드 도메인 |
| EKS | `eks.describe_cluster()` | 클러스터 SG + 추가 SG |
| DocumentDB | `docdb.describe_db_clusters()` | MongoDB 호환 |

#### 중간 우선순위 (9개)
| 서비스 | API | 비고 |
|--------|-----|------|
| MSK (Kafka) | `kafka.list_clusters_v2()` | 브로커 노드 SG |
| EMR | `emr.describe_cluster()` | Master/Slave/Service SG |
| SageMaker | `sagemaker.describe_notebook_instance()` | VPC 연결 노트북 |
| MWAA (Airflow) | `mwaa.get_environment()` | 네트워크 설정 SG |
| DMS | `dms.describe_replication_instances()` | 복제 인스턴스 SG |
| EFS | `efs.describe_mount_target_security_groups()` | 마운트 타겟별 SG |
| DAX | `dax.describe_clusters()` | DynamoDB 캐시 |
| Neptune | `neptune.describe_db_clusters()` | 그래프 DB |
| MemoryDB | `memorydb.describe_clusters()` | Redis 호환 |

### 프론트엔드 업데이트
- 15개 신규 리소스 타입별 색상/스타일 추가 (그래프 노드 + 배지)

---

### 다음 단계 (TODO)
- [ ] 실제 AWS 환경에서 데이터 수집 테스트
- [ ] 성능 확인 (SG 수백 개 규모에서 그래프 렌더링)
- [ ] 필요 시 UI 개선 (그래프 레이아웃, 상세 패널)
- [ ] Phase 2 기능 검토 (멀티 계정, 변경 이력 등)
