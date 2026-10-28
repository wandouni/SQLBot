# Author: Junjun
# Date: 2025/7/1
import json
from datetime import timedelta
from typing import Optional

from fastapi import HTTPException, APIRouter, Request
from fastapi.responses import JSONResponse

from apps.chat.api.chat import create_chat, question_answer_inner
from apps.chat.models.chat_model import (
    ChatMcp, CreateChat, ChatStart, McpQuestion, McpAsk, McpAssistant,
    ChatQuestion, ChatFinishStep, McpDs, ChatToken, WsMcp, Chat,
)
from apps.datasource.crud.datasource import get_datasource_list
from apps.mcp.auth import McpScope, resolve_mcp_principal
from apps.system.crud.aimodel_manage import get_ai_model_list_by_workspace
from apps.system.crud.user import authenticate, user_ws_options
from apps.system.schemas.system_schema import BaseUserDTO, AssistantHeader
from common.audit.models.log_model import OperationType, OperationModules
from common.audit.schemas.logger_decorator import LogConfig, system_log
from common.audit.schemas.request_context import RequestContext
from common.core.config import settings
from common.core.deps import SessionDep, Trans
from common.core.schemas import Token, XOAuth2PasswordBearer
from common.core.security import create_access_token

reusable_oauth2 = XOAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token"
)

router = APIRouter(tags=["mcp"], prefix="/mcp")


@router.post("/access_token", operation_id="access_token")
async def access_token(session: SessionDep, request: Request, chat: ChatToken):
    if request.headers.get('authorization'):
        # Scoped MCP connections must never exchange credentials for a full user JWT.
        raise HTTPException(status_code=403, detail="Scoped MCP tokens cannot use access_token")

    user: BaseUserDTO = authenticate(session=session, account=chat.username, password=chat.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect account or password")

    if not user.oid or user.oid == 0:
        raise HTTPException(status_code=400, detail="No associated workspace, Please contact the administrator")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    user_dict = user.to_dict()
    t = Token(access_token=create_access_token(
        user_dict, expires_delta=access_token_expires
    ))
    # c = create_chat(session, user, CreateChat(origin=1), False)
    return {"access_token": t.access_token}


@router.post("/mcp_start", operation_id="mcp_start")
@system_log(LogConfig(
    operation_type=OperationType.CREATE,
    module=OperationModules.CHAT,
    result_id_expr="id",
    save_on_success_only=True
))
async def mcp_start(session: SessionDep, trans: Trans, request: Request, chat: ChatStart):
    scope: Optional[McpScope] = None
    res_token: Optional[str] = None
    user = None

    if request.headers.get('authorization') or chat.token:
        principal = await resolve_mcp_principal(session, request, chat.token)
        user = principal.user
        scope = principal.scope
        res_token = None if scope is not None else chat.token
    else:
        user = authenticate(session=session, account=chat.username, password=chat.password)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect account or password")

        if not user.oid or user.oid == 0:
            raise HTTPException(status_code=400, detail="No associated workspace, Please contact the administrator")
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        user_dict = user.to_dict()
        t = Token(access_token=create_access_token(
            user_dict, expires_delta=access_token_expires
        ))
        res_token = t.access_token

    if scope is not None:
        if chat.oid and int(chat.oid) != scope.oid:
            raise HTTPException(status_code=403, detail="Token is scoped to another workspace")
        user.oid = scope.oid
    elif chat.oid:
        w_list = await user_ws_options(session, user.id, trans)
        oid_list = [item.id for item in w_list]
        if int(chat.oid) not in oid_list:
            raise HTTPException(status_code=400, detail="The current user is not in the selected workspace")

        user.oid = int(chat.oid)

    request_ctx = RequestContext.get_request()
    request_ctx.state.current_user = user

    if scope is not None:
        try:
            c = create_chat(
                session,
                user,
                CreateChat(origin=1, datasource=scope.datasource_id),
                True,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        c = create_chat(session, user, CreateChat(origin=1), False)
    return {"access_token": res_token, "chat_id": c.id}


@router.post("/mcp_ws_list", operation_id="mcp_ws_list")
async def ws_list(session: SessionDep, trans: Trans, request: Request, token: Optional[str] = None):
    principal = await resolve_mcp_principal(session, request, token)
    session_user = principal.user
    options = await user_ws_options(session, session_user.id, trans)
    if principal.scope is not None:
        options = [item for item in options if int(item.id) == principal.scope.oid]
    return options


@router.post("/mcp_ds_list", operation_id="mcp_datasource_list")
async def datasource_list(session: SessionDep, trans: Trans, request: Request, mcp_ds: McpDs):
    principal = await resolve_mcp_principal(session, request, mcp_ds.token)
    session_user = principal.user

    if principal.scope is not None:
        if mcp_ds.oid and int(mcp_ds.oid) != principal.scope.oid:
            raise HTTPException(status_code=403, detail="Token is scoped to another workspace")
        session_user.oid = principal.scope.oid
    elif mcp_ds.oid:
        w_list = await user_ws_options(session, session_user.id, trans)
        oid_list = [item.id for item in w_list]
        if int(mcp_ds.oid) not in oid_list:
            raise HTTPException(status_code=400, detail="The current user is not in the selected workspace")

        session_user.oid = int(mcp_ds.oid)

    ds_list = get_datasource_list(session=session, user=session_user)
    result = []
    for item in ds_list:
        if principal.scope is not None and int(item.id) != principal.scope.datasource_id:
            continue
        dic = item.__dict__
        dic.pop('embedding', None)
        dic.pop('table_relation', None)
        dic.pop('recommended_config', None)
        dic.pop('configuration', None)
        result.append(dic)
    return result


@router.post("/mcp_model_list", operation_id="mcp_model_list")
async def get_model_by_ws(session: SessionDep, request: Request, mcp_oid: WsMcp):
    if request.headers.get('authorization'):
        principal = await resolve_mcp_principal(session, request)
        oid = principal.scope.oid if principal.scope is not None else int(principal.user.oid)
    else:
        oid = int(mcp_oid.oid)
    return get_ai_model_list_by_workspace(session, oid, False)


@router.post("/mcp_question", operation_id="mcp_question")
async def mcp_question(session: SessionDep, trans: Trans, request: Request, chat: McpQuestion):
    principal = await resolve_mcp_principal(session, request, chat.token)
    session_user = principal.user
    scope = principal.scope
    lang = chat.lang
    if lang in ["zh-CN", "zh-TW", "en", "ko-KR", "th-TH"]:
        session_user.language = lang

    c = session.query(Chat).filter(Chat.id == chat.chat_id).first()
    if not c:
        raise HTTPException(status_code=400, detail="Chat ID is not exist")

    ds_id: Optional[int] = None
    if scope is not None:
        if (
            int(c.create_by or 0) != scope.uid
            or int(c.oid or 0) != scope.oid
            or int(c.datasource or 0) != scope.datasource_id
        ):
            raise HTTPException(status_code=403, detail="Chat is outside the MCP token scope")
        session_user.oid = scope.oid
        ds_id = scope.datasource_id
    else:
        chat_oid = c.oid
        if chat_oid:
            w_list = await user_ws_options(session, session_user.id, trans)
            oid_list = [item.id for item in w_list]
            if int(chat_oid) not in oid_list:
                raise HTTPException(status_code=400, detail="The current user is not in the selected workspace")

            session_user.oid = int(chat_oid)

        if chat.datasource_id:
            if isinstance(chat.datasource_id, str):
                if chat.datasource_id.strip() == "":
                    ds_id = None
                else:
                    try:
                        ds_id = int(chat.datasource_id.strip())
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid datasource ID")
            elif isinstance(chat.datasource_id, int):
                ds_id = chat.datasource_id
            else:
                raise HTTPException(status_code=400, detail="Invalid datasource ID")

    mcp_chat = ChatMcp(token=chat.token or '', chat_id=chat.chat_id, question=chat.question, datasource_id=ds_id,
                       custom_model=chat.custom_model)

    return await question_answer_inner(session=session, current_user=session_user, request_question=mcp_chat,
                                       in_chat=False,
                                       stream=False if scope is not None else chat.stream,
                                       return_img=chat.return_img)


@router.post("/mcp_ask", operation_id="mcp_ask")
async def mcp_ask(session: SessionDep, trans: Trans, request: Request, ask: McpAsk):
    """Answer one question and return the chat id for optional follow-ups."""
    principal = await resolve_mcp_principal(session, request, ask.token)
    session_user = principal.user
    scope = principal.scope
    lang = ask.lang
    if lang in ["zh-CN", "zh-TW", "en", "ko-KR", "th-TH"]:
        session_user.language = lang

    if scope is not None:
        session_user.oid = scope.oid
        datasource_id: Optional[int] = scope.datasource_id
    else:
        datasource_id = ask.datasource_id

    chat_id = ask.chat_id
    if chat_id:
        c = session.query(Chat).filter(Chat.id == chat_id).first()
        if not c:
            raise HTTPException(status_code=400, detail="Chat ID is not exist")
        if scope is not None:
            if (
                int(c.create_by or 0) != scope.uid
                or int(c.oid or 0) != scope.oid
                or int(c.datasource or 0) != scope.datasource_id
            ):
                raise HTTPException(status_code=403, detail="Chat is outside the MCP token scope")
        else:
            if int(c.create_by or 0) != int(session_user.id):
                raise HTTPException(status_code=403, detail="Chat does not belong to current user")
            if c.oid:
                w_list = await user_ws_options(session, session_user.id, trans)
                oid_list = [item.id for item in w_list]
                if int(c.oid) not in oid_list:
                    raise HTTPException(status_code=400, detail="The current user is not in the selected workspace")
                session_user.oid = int(c.oid)
    else:
        if not datasource_id:
            raise HTTPException(status_code=400, detail="Datasource is required when chat_id is missing")
        try:
            created = create_chat(
                session,
                session_user,
                CreateChat(origin=1, datasource=datasource_id),
                True,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        chat_id = created.id

    mcp_chat = ChatMcp(token=ask.token or '', chat_id=chat_id, question=ask.question, datasource_id=datasource_id,
                       custom_model=ask.custom_model)

    answer = await question_answer_inner(session=session, current_user=session_user, request_question=mcp_chat,
                                         in_chat=False, stream=False, return_img=ask.return_img)
    if isinstance(answer, JSONResponse):
        try:
            payload = json.loads(answer.body)
        except (TypeError, ValueError):
            payload = {"content": answer.body.decode(errors="ignore") if isinstance(answer.body, bytes) else str(answer.body)}
    elif isinstance(answer, dict):
        payload = answer
    else:
        payload = {"answer": answer}
    return {"chat_id": chat_id, **payload}


# Cordys crm
@router.post("/mcp_assistant", operation_id="mcp_assistant")
async def mcp_assistant(session: SessionDep, request: Request, chat: McpAssistant):
    if request.headers.get('authorization'):
        # Scoped MCP tokens are bound to a datasource and cannot drive third-party assistants.
        await resolve_mcp_principal(session, request)
        raise HTTPException(status_code=403, detail="Scoped MCP tokens cannot use mcp_assistant")

    session_user = BaseUserDTO(**{
        "id": -1, "account": 'sqlbot-mcp-assistant', "oid": 1, "assistant_id": -1, "password": '', "language": "zh-CN"
    })
    # session_user: UserModel = get_db_user(session=session, user_id=1)
    # session_user.oid = 1
    c = create_chat(session, session_user, CreateChat(origin=1), False)

    # build assistant param
    configuration = {"endpoint": chat.url}
    # authorization = [{"key": "x-de-token",
    #                 "value": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzU4NTEyMDA2fQ.3NR-pgnADLdXZtI3dXX5-LuxfGYRvYD9kkr2de7KRP0",
    #                 "target": "header"}]
    mcp_assistant_header = AssistantHeader(id=1, name='mcp_assist', domain='', type=1,
                                           configuration=json.dumps(configuration),
                                           certificate=chat.authorization)

    # assistant question
    mcp_chat = ChatQuestion(chat_id=c.id, question=chat.question)
    # ask
    return await question_answer_inner(session=session, current_user=session_user, request_question=mcp_chat,
                                       current_assistant=mcp_assistant_header,
                                       in_chat=False, stream=chat.stream, finish_step=ChatFinishStep.QUERY_DATA)
