import { Link } from 'react-router-dom';

export function NotFound() {
  return (
    <div className="panel">
      <h1>NOT FOUND</h1>
      <p className="muted">This route does not exist in the investigation workspace.</p>
      <Link to="/" className="btn">← Dashboard</Link>
    </div>
  );
}
