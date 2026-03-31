# Changelog

## [1.0.0] - 2026-03-31

### Features

- **23개 AWS 리소스 타입 수집** — EC2, RDS, Aurora, ALB/NLB, Lambda, ECS, EKS, ElastiCache, Redshift, OpenSearch, DocumentDB, MSK, EMR, SageMaker, MWAA, DMS, EFS, DAX, Neptune, MemoryDB, VPC Endpoints, ENI, Classic LB
- **보안 분석** — 미사용 SG, 위험 규칙(critical/high/medium), 순환 참조, 중복 규칙, default SG 규칙 검토
- **그래프 시각화** — Cytoscape.js 기반 네트워크 그래프, VPC별 경계선 표시, 위험도별 색상 구분
- **테이블 뷰** — 정렬 가능한 SG 목록 (그래프/테이블 전환)
- **멀티 계정 지원** — `~/.aws/config` 프로파일 자동 감지, 동일 계정 중복 제거
- **필터링** — Profile, VPC, Risk Level, 검색어 기반 필터링
- **내보내기** — 미사용 SG 목록 JSON/CSV 다운로드
- **병렬 수집** — ThreadPoolExecutor 기반 동시 수집 (최대 10 워커)
- **데이터 캐싱** — 수집 데이터 로컬 파일 캐시 (`sg_data_cache.json`)
- **Docker 지원** — Dockerfile, docker-compose.yml 제공
- **인터랙티브 실행** — `run.sh` 화살표 키 메뉴로 간편 실행
