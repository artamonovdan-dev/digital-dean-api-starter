"""Маршрути ресурсу «студент» (/api/v1/students)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.repositories.student_repository import (
    EmailAlreadyExistsError,
    StudentNotFoundError,
    StudentRepository,
    get_student_repository,
)
from app.schemas.student import ErrorResponse, StudentCreate, StudentRead, StudentUpdate
from app.config import institution_config


router = APIRouter(prefix="/students", tags=["students"])

RepositoryDep = Annotated[StudentRepository, Depends(get_student_repository)]

NOT_FOUND = {404: {"model": ErrorResponse, "description": "Запис не знайдено"}}
CONFLICT = {409: {"model": ErrorResponse, "description": "Електронна адреса вже використовується"}}


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "student_not_found", "message": "Студента з таким ідентифікатором не знайдено"},
    )


def _email_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "email_conflict", "message": "Студент із такою електронною адресою вже існує"},
    )


@router.post(
    "",
    response_model=StudentRead,
    status_code=status.HTTP_201_CREATED,
    responses=CONFLICT,
    summary="Створити запис студента",
)
def create_student(payload: StudentCreate, repository: RepositoryDep) -> StudentRead:
    try:
        return repository.create(payload)
    except EmailAlreadyExistsError:
        raise _email_conflict() from None


@router.get("", response_model=list[StudentRead], summary="Отримати список студентів")
def list_students(
    repository: RepositoryDep,
    enrollment_year: Annotated[
        int | None,
        Query(
            ge=institution_config.enrollment_year_min,
            le=institution_config.enrollment_year_max,
            description="Фільтр за роком вступу",
        ),
    ] = None,
) -> list[StudentRead]:
    return repository.list_all(enrollment_year=enrollment_year)


@router.get(
    "/{student_id}",
    response_model=StudentRead,
    responses=NOT_FOUND,
    summary="Отримати студента за UUID",
)
def get_student(student_id: UUID, repository: RepositoryDep) -> StudentRead:
    try:
        return repository.get(student_id)
    except StudentNotFoundError:
        raise _not_found() from None


@router.patch(
    "/{student_id}",
    response_model=StudentRead,
    responses={**NOT_FOUND, **CONFLICT},
    summary="Частково змінити дозволені поля",
)
def update_student(student_id: UUID, changes: StudentUpdate, repository: RepositoryDep) -> StudentRead:
    try:
        return repository.update(student_id, changes)
    except StudentNotFoundError:
        raise _not_found() from None
    except EmailAlreadyExistsError:
        raise _email_conflict() from None
