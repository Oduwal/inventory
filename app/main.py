from __future__ import annotations

from pathlib import Path

import pandas as pd
from fastapi import FastAPI, Request, Depends, Form, UploadFile, File
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from .database import Base, engine, get_db
from .models import Item, Transaction
from .services import (
    get_items_with_stock,
    get_item_with_stock,
    get_low_stock,
    get_recent_transactions,
    dashboard_stats,
    dashboard_kpis,
    stock_by_category,
    in_out_last_7_days,
    top_items_by_stock,
)

app = FastAPI(title="Inventory Keeper")

# DB tables
Base.metadata.create_all(bind=engine)

# Paths (Windows-safe)
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def redirect(url: str):
    return RedirectResponse(url=url, status_code=303)


# ---------------- Dashboard ----------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = dashboard_stats(db)

    total_stock, inventory_value = dashboard_kpis(db)
    cat_rows = stock_by_category(db)
    in7, out7 = in_out_last_7_days(db)
    top_rows = top_items_by_stock(db, limit=5)
    low_rows = get_low_stock(db)[:5]

    categories = [c for (c, _s) in cat_rows]
    cat_stock = [int(s) for (_c, s) in cat_rows]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            **stats,
            "total_stock": total_stock,
            "inventory_value": inventory_value,
            "in7": in7,
            "out7": out7,
            "top_rows": top_rows,
            "low_rows": low_rows,
            "categories": categories,
            "cat_stock": cat_stock,
        },
    )


# ---------------- Items ----------------

@app.get("/items", response_class=HTMLResponse)
def items_list(request: Request, q: str = "", db: Session = Depends(get_db)):
    rows = get_items_with_stock(db)
    q_lower = q.strip().lower()

    if q_lower:
        filtered = []
        for item, stock in rows:
            sku = (item.sku or "").lower()
            name = (item.name or "").lower()
            cat = (item.category or "").lower()
            if q_lower in sku or q_lower in name or q_lower in cat:
                filtered.append((item, stock))
        rows = filtered

    return templates.TemplateResponse(
        "items_list.html",
        {"request": request, "rows": rows, "q": q},
    )


@app.get("/items/new", response_class=HTMLResponse)
def item_new_form(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse(
        "item_form.html",
        {"request": request, "mode": "new", "item": None, "error": error},
    )


@app.post("/items/new")
def item_create(
    sku: str = Form(default=""),
    name: str = Form(...),
    category: str = Form(default=""),
    reorder_level: int = Form(default=0),
    cost_price: float = Form(default=0),
    selling_price: float = Form(default=0),
    db: Session = Depends(get_db),
):
    sku_clean = sku.strip() or None

    if sku_clean:
        existing = db.scalar(select(Item).where(Item.sku == sku_clean))
        if existing:
            return redirect("/items/new?error=SKU+already+exists")

    item = Item(
        sku=sku_clean,
        name=name.strip(),
        category=category.strip() or None,
        unit="pcs",
        reorder_level=max(0, int(reorder_level)),
        cost_price=max(0.0, float(cost_price)),
        selling_price=max(0.0, float(selling_price)),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return redirect(f"/items/{item.id}")


@app.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail(request: Request, item_id: int, db: Session = Depends(get_db)):
    row = get_item_with_stock(db, item_id)
    if not row:
        return HTMLResponse("Item not found", status_code=404)

    item, stock = row

    tx_stmt = (
        select(Transaction)
        .where(Transaction.item_id == item_id)
        .order_by(desc(Transaction.created_at))
        .limit(50)
    )
    txs = db.scalars(tx_stmt).all()

    return templates.TemplateResponse(
        "item_detail.html",
        {"request": request, "item": item, "stock": stock, "txs": txs},
    )


@app.get("/items/{item_id}/edit", response_class=HTMLResponse)
def item_edit_form(request: Request, item_id: int, db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        return HTMLResponse("Item not found", status_code=404)

    error = request.query_params.get("error")
    return templates.TemplateResponse(
        "item_form.html",
        {"request": request, "mode": "edit", "item": item, "error": error},
    )


@app.post("/items/{item_id}/edit")
def item_update(
    item_id: int,
    sku: str = Form(default=""),
    name: str = Form(...),
    category: str = Form(default=""),
    reorder_level: int = Form(default=0),
    cost_price: float = Form(default=0),
    selling_price: float = Form(default=0),
    db: Session = Depends(get_db),
):
    item = db.get(Item, item_id)
    if not item:
        return HTMLResponse("Item not found", status_code=404)

    sku_clean = sku.strip() or None
    if sku_clean:
        existing = db.scalar(select(Item).where(Item.sku == sku_clean, Item.id != item_id))
        if existing:
            return redirect(f"/items/{item_id}/edit?error=SKU+already+exists")

    item.sku = sku_clean
    item.name = name.strip()
    item.category = category.strip() or None
    item.reorder_level = max(0, int(reorder_level))
    item.cost_price = max(0.0, float(cost_price))
    item.selling_price = max(0.0, float(selling_price))

    db.commit()
    return redirect(f"/items/{item_id}")


@app.post("/items/{item_id}/delete")
def item_delete(item_id: int, db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        return HTMLResponse("Item not found", status_code=404)

    db.delete(item)
    db.commit()
    return redirect("/items")


# ---------------- Transactions ----------------

@app.get("/transactions", response_class=HTMLResponse)
def transactions_list(request: Request, db: Session = Depends(get_db)):
    txs = get_recent_transactions(db, limit=200)
    return templates.TemplateResponse("transactions_list.html", {"request": request, "txs": txs})


@app.get("/transactions/new", response_class=HTMLResponse)
def tx_new_form(
    request: Request,
    item_id: int | None = None,
    tx_type: str = "IN",
    db: Session = Depends(get_db),
):
    rows = get_items_with_stock(db)
    items = [item for item, _stock in rows]
    tx_type_clean = tx_type if tx_type in ("IN", "OUT") else "IN"

    error = request.query_params.get("error")
    return templates.TemplateResponse(
        "tx_form.html",
        {
            "request": request,
            "items": items,
            "selected_item_id": item_id,
            "tx_type": tx_type_clean,
            "error": error,
        },
    )


@app.post("/transactions/new")
def tx_create(
    item_id: int = Form(...),
    tx_type: str = Form(...),
    quantity: int = Form(...),
    reference: str = Form(default=""),
    note: str = Form(default=""),
    db: Session = Depends(get_db),
):
    if tx_type not in ("IN", "OUT"):
        return redirect("/transactions/new?error=Invalid+type")

    if quantity <= 0:
        return redirect("/transactions/new?error=Quantity+must+be+greater+than+0")

    item = db.get(Item, item_id)
    if not item:
        return redirect("/transactions/new?error=Item+not+found")

    tx = Transaction(
        item_id=item_id,
        type=tx_type,
        quantity=int(quantity),
        reference=reference.strip() or None,
        note=note.strip() or None,
    )
    db.add(tx)
    db.commit()
    return redirect(f"/items/{item_id}")


# ---------------- Low stock ----------------

@app.get("/low-stock", response_class=HTMLResponse)
def low_stock(request: Request, db: Session = Depends(get_db)):
    rows = get_low_stock(db)
    return templates.TemplateResponse("low_stock.html", {"request": request, "rows": rows})


# ---------------- Import ----------------

@app.get("/import", response_class=HTMLResponse)
def import_page(request: Request):
    return templates.TemplateResponse("import.html", {"request": request, "message": None})


@app.post("/import", response_class=HTMLResponse)
async def import_items(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    filename = (file.filename or "").lower()

    if not (filename.endswith(".csv") or filename.endswith(".xlsx")):
        return templates.TemplateResponse(
            "import.html",
            {"request": request, "message": "Upload a .csv or .xlsx file."},
        )

    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(file.file)
        else:
            df = pd.read_excel(file.file)
    except Exception:
        return templates.TemplateResponse(
            "import.html",
            {"request": request, "message": "File could not be read. Check the format and try again."},
        )

    df.columns = [str(c).strip().lower() for c in df.columns]

    if "name" not in set(df.columns):
        return templates.TemplateResponse(
            "import.html",
            {"request": request, "message": "File must have at least a 'name' column."},
        )

    created = 0
    updated = 0

    for _, row in df.iterrows():
        name = str(row.get("name", "")).strip()
        if not name or name.lower() == "nan":
            continue

        sku_val = row.get("sku", None)
        sku = None if pd.isna(sku_val) else str(sku_val).strip()
        sku = sku or None

        category_val = row.get("category", None)
        category = None if pd.isna(category_val) else str(category_val).strip()
        category = category or None

        reorder_val = row.get("reorder_level", 0)
        try:
            reorder_level = int(reorder_val) if not pd.isna(reorder_val) else 0
        except Exception:
            reorder_level = 0

        cost_val = row.get("cost_price", 0)
        sell_val = row.get("selling_price", 0)
        try:
            cost_price = float(cost_val) if not pd.isna(cost_val) else 0.0
        except Exception:
            cost_price = 0.0
        try:
            selling_price = float(sell_val) if not pd.isna(sell_val) else 0.0
        except Exception:
            selling_price = 0.0

        item = None
        if sku:
            item = db.query(Item).filter(Item.sku == sku).first()

        if item:
            item.name = name
            item.category = category
            item.reorder_level = max(0, reorder_level)
            item.cost_price = max(0.0, cost_price)
            item.selling_price = max(0.0, selling_price)
            updated += 1
        else:
            db.add(
                Item(
                    sku=sku,
                    name=name,
                    category=category,
                    unit="pcs",
                    reorder_level=max(0, reorder_level),
                    cost_price=max(0.0, cost_price),
                    selling_price=max(0.0, selling_price),
                )
            )
            created += 1

    db.commit()
    msg = f"Import complete. Created {created}, updated {updated}."
    return templates.TemplateResponse("import.html", {"request": request, "message": msg})