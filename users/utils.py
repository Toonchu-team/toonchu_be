import random

FIRST_NAMES = [
    "외로운",
    "행복한",
    "심심한",
    "용감한",
    "차가운",
    "따뜻한",
    "멋진",
    "귀여운",
    "고독한",
    "영리한",
]

# 고양이 품종 (last_name)
LAST_NAMES = [
    "코숏",
    "러시안블루",
    "샴",
    "스핑크스",
    "먼치킨",
    "메인쿤",
    "페르시안",
    "노르웨이숲",
    "뱅갈",
    "스코티시폴드",
]

# 히든 닉네임 목록 (5% 확률)
HIDDEN_NICKNAMES = [
    "코가 짧은 코숏",
    "야비한 아비시니안",
    "하나 둘 샴",
    "렉걸린 렉돌",
    "가깝고도 먼치킨",
    "스코티쉬 플립",
    "손병호게임 숙호티씨 접어",
]


def RendomNickName():
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)

    # 확률 2%로 적용
    if random.random() < 0.02:  # 히든 닉네임 2% 확률
        return random.choice(HIDDEN_NICKNAMES)

    return f"{first_name} {last_name}"  # 일반닉네임 98% 확률
