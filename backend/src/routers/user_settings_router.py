from fastapi import APIRouter, HTTPException, status
from src.services import UserSettingsService
from src.schemas import UserSettings, UserSettingsBase, ACCENT_COLOR_PRESETS

router = APIRouter()


@router.get("/user-settings", response_model=UserSettings, operation_id="GetUserSettings")
def get_user_settings():
    try:
        return UserSettingsService.get_user_settings()
    except Exception as e:
        print(f"Exception happened when getting user settings: ", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not get user settings",
        )


@router.put("/user-settings", response_model=UserSettings, operation_id="UpdateUserSettings")
def update_user_settings(data: UserSettingsBase):
    if data.accent_color not in ACCENT_COLOR_PRESETS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown accent_color: {data.accent_color!r}",
        )
    if data.global_max_concurrent_agents < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="global_max_concurrent_agents must be at least 1.",
        )

    try:
        return UserSettingsService.update_user_settings(data)
    except Exception as e:
        print(f"Exception happened when updating user settings: ", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update user settings",
        )
