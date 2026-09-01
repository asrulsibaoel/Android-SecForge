import { useMemo, useState, type ReactNode } from 'react';

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number;
  sortable?: boolean;
}

// Reusable table with DETERMINISTIC explicit sorting and pagination (§4/§24/§29).
// Sorting is stable: ties break on the row's stable identity. No client-side
// analytical computation happens here — it only orders/paginates given rows.
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  pageSize = 25,
  initialSort,
  emptyLabel = 'NO ROWS',
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  pageSize?: number;
  initialSort?: { key: string; dir: 'asc' | 'desc' };
  emptyLabel?: string;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(initialSort ?? null);
  const [page, setPage] = useState(0);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = col.sortValue!(a);
      const vb = col.sortValue!(b);
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      // deterministic tie-break on stable key
      return rowKey(a) < rowKey(b) ? -1 : 1;
    });
  }, [rows, sort, columns, rowKey]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clampedPage = Math.min(page, pageCount - 1);
  const pageRows = sorted.slice(clampedPage * pageSize, clampedPage * pageSize + pageSize);

  function toggleSort(key: string) {
    setPage(0);
    setSort((s) => {
      if (!s || s.key !== key) return { key, dir: 'asc' };
      if (s.dir === 'asc') return { key, dir: 'desc' };
      return null;
    });
  }

  if (rows.length === 0) return <div className="state state--empty" role="status"><strong>{emptyLabel}</strong></div>;

  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.sortable !== false && c.sortValue ? (
                  <button className="th-sort" onClick={() => toggleSort(c.key)} aria-label={`Sort by ${c.header}`}>
                    {c.header}
                    {sort?.key === c.key ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : ''}
                  </button>
                ) : (
                  c.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {pageRows.map((row) => (
            <tr
              key={rowKey(row)}
              className={onRowClick ? 'row-clickable' : ''}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter') onRowClick(row); } : undefined}
            >
              {columns.map((c) => (
                <td key={c.key}>{c.render ? c.render(row) : String((row as any)[c.key] ?? '')}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {pageCount > 1 && (
        <div className="pager">
          <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={clampedPage === 0}>Prev</button>
          <span className="muted">Page {clampedPage + 1} / {pageCount} · {sorted.length} rows</span>
          <button onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} disabled={clampedPage >= pageCount - 1}>Next</button>
        </div>
      )}
    </div>
  );
}
