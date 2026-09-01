import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { GraphView } from '../components/GraphView';
import type { GraphEdge, GraphNode } from '../api/types';

function nodes(n: number): GraphNode[] {
  return Array.from({ length: n }, (_, i) => ({ id: `N${i}`, type: i % 2 ? 'FINDING' : 'METHOD', label: `node ${i}` }));
}

describe('GraphView is a bounded renderer (§6/§23)', () => {
  it('bounds rendering and shows TRUNCATED, never silently dropping nodes', () => {
    render(<GraphView nodes={nodes(500)} edges={[]} maxNodes={10} />);
    expect(screen.getByText(/TRUNCATED/)).toBeInTheDocument();
    expect(screen.getByText(/showing 10 of 500/)).toBeInTheDocument();
  });

  it('does not show TRUNCATED when under the bound', () => {
    render(<GraphView nodes={nodes(5)} edges={[]} maxNodes={400} />);
    expect(screen.queryByText(/TRUNCATED/)).toBeNull();
  });

  it('selecting a node invokes the callback with backend node data', () => {
    const onSelect = vi.fn();
    render(<GraphView nodes={nodes(3)} edges={[]} onSelectNode={onSelect} />);
    const node = screen.getByRole('button', { name: /METHOD: node 0/ });
    fireEvent.click(node);
    expect(onSelect).toHaveBeenCalledOnce();
    expect(onSelect.mock.calls[0][0].id).toBe('N0');
  });

  it('an UNKNOWN-confidence edge is drawn dashed and labelled, not as confirmed', () => {
    const ns = nodes(2);
    const edges: GraphEdge[] = [{ id: 'E0', source: 'N0', target: 'N1', type: 'REACHES', confidence: 'UNKNOWN' }];
    const { container } = render(<GraphView nodes={ns} edges={edges} />);
    const line = container.querySelector('line');
    expect(line?.getAttribute('stroke-dasharray')).toBe('4 4');
    expect(container.querySelector('.graph-edge--unknown')).toBeTruthy();
  });
});
