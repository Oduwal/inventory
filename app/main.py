from app.core import app
from app.routers import auth
from app.routers import dashboard
from app.routers import branches
from app.routers import items
from app.routers import agents
from app.routers import deliveries
from app.routers import notifications
from app.routers import vetting
from app.routers import finances
from app.routers import admin
from app.routers import static
from app.routers import transfers
from app.routers import whatsapp

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(branches.router)
app.include_router(items.router)
app.include_router(deliveries.router)
app.include_router(agents.router)
app.include_router(notifications.router)
app.include_router(vetting.router)
app.include_router(finances.router)
app.include_router(admin.router)
app.include_router(static.router)
app.include_router(transfers.router)
app.include_router(whatsapp.router)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app.main:app', host='0.0.0.0', port=8000, reload=True)
