#!/usr/bin/env bash
set -euo pipefail

# ─── Colors ───
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BLUE='\033[34m'
RESET='\033[0m'
BG_BLUE='\033[44m'
WHITE='\033[97m'

# ─── Menu items ───
TITLES=("Local Setup + Run" "Local Run" "Docker Compose" "Docker Compose Down" "Clean")
DESCS=("Python venv 세팅 후 서버 실행" "이미 세팅된 venv로 서버 실행" "Docker로 빌드 + 실행" "Docker 컨테이너 종료" "venv, 캐시 등 전부 삭제")

SELECTED=0
TOTAL=${#TITLES[@]}

# ─── Draw ───
draw_menu() {
  # Header
  echo -e ""
  echo -e "  ${BOLD}${CYAN}AWS Security Group Review Dashboard${RESET}"
  echo -e "  ${DIM}────────────────────────────────────────${RESET}"
  echo -e ""

  for i in "${!TITLES[@]}"; do
    local title="${TITLES[$i]}"
    local desc="${DESCS[$i]}"
    local pad=$(( 22 - ${#title} ))
    local spacing=$(printf '%*s' "$pad" '')

    if [[ $i -eq $SELECTED ]]; then
      echo -e "  ${BG_BLUE}${WHITE}${BOLD} > ${title}${spacing}${RESET} ${DIM}${desc}${RESET}"
    else
      echo -e "     ${BOLD}${title}${RESET}${spacing} ${DIM}${desc}${RESET}"
    fi
  done

  echo -e ""
  echo -e "  ${DIM}↑↓ 선택  Enter 실행  q 종료${RESET}"
  echo -e ""
}

clear_menu() {
  # Move up and clear lines: header(4) + items + footer(3)
  local lines=$((TOTAL + 7))
  for ((i = 0; i < lines; i++)); do
    tput cuu1
    tput el
  done
}

# ─── Actions ───
check_python() {
  if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo -e "  ${RED}Python 3.9+ 가 필요합니다.${RESET}"
    exit 1
  fi
  PYTHON=$(command -v python3 || command -v python)
}

check_docker() {
  if ! command -v docker &>/dev/null; then
    echo -e "  ${RED}Docker가 설치되어 있지 않습니다.${RESET}"
    exit 1
  fi
}

action_setup_and_run() {
  check_python
  echo -e "  ${CYAN}[1/3]${RESET} venv 생성 중..."
  $PYTHON -m venv .venv

  echo -e "  ${CYAN}[2/3]${RESET} 의존성 설치 중..."
  .venv/bin/pip install -q -r requirements.txt

  echo -e "  ${GREEN}[3/3]${RESET} 서버를 시작합니다."
  echo -e ""
  echo -e "  ${BOLD}${GREEN}→ http://localhost:5000${RESET}"
  echo -e ""
  .venv/bin/python server.py
}

action_run() {
  if [[ ! -d .venv ]]; then
    echo -e "  ${YELLOW}venv가 없습니다. 먼저 세팅을 진행합니다.${RESET}"
    echo ""
    action_setup_and_run
    return
  fi
  echo -e "  ${GREEN}서버를 시작합니다.${RESET}"
  echo -e ""
  echo -e "  ${BOLD}${GREEN}→ http://localhost:5000${RESET}"
  echo -e ""
  .venv/bin/python server.py
}

action_docker_up() {
  check_docker
  echo -e "  ${CYAN}Docker Compose로 실행합니다.${RESET}"
  echo -e ""
  echo -e "  ${BOLD}${GREEN}→ http://localhost:5000${RESET}"
  echo -e ""
  docker compose up --build
}

action_docker_down() {
  check_docker
  echo -e "  ${CYAN}Docker Compose를 종료합니다.${RESET}"
  docker compose down
  echo -e "  ${GREEN}종료 완료.${RESET}"
}

action_clean() {
  echo -e "  ${YELLOW}정리 중...${RESET}"
  rm -rf .venv __pycache__ sg_data_cache.json
  echo -e "  ${GREEN}완료. (.venv, __pycache__, sg_data_cache.json 삭제됨)${RESET}"
}

run_action() {
  echo -e ""
  case $SELECTED in
    0) action_setup_and_run ;;
    1) action_run ;;
    2) action_docker_up ;;
    3) action_docker_down ;;
    4) action_clean ;;
  esac
}

# ─── Main ───
main() {
  # Hide cursor
  tput civis
  trap 'tput cnorm' EXIT

  draw_menu

  while true; do
    # Read single keypress
    IFS= read -rsn1 key

    case "$key" in
      # Arrow keys: ESC [ A/B
      $'\x1b')
        read -rsn2 seq
        case "$seq" in
          '[A') # Up
            ((SELECTED > 0)) && ((SELECTED--))
            ;;
          '[B') # Down
            ((SELECTED < TOTAL - 1)) && ((SELECTED++))
            ;;
        esac
        ;;
      # Enter
      '')
        clear_menu
        run_action
        break
        ;;
      # q or Q
      q|Q)
        clear_menu
        echo -e "  ${DIM}종료합니다.${RESET}"
        break
        ;;
    esac

    clear_menu
    draw_menu
  done
}

main
