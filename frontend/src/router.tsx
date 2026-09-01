import { createBrowserRouter } from 'react-router-dom';
import { RootLayout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { AnalysisLayout } from './pages/AnalysisLayout';
import { Overview } from './pages/Overview';
import { Findings } from './pages/Findings';
import { AttackSurface } from './pages/AttackSurface';
import { GraphPage } from './pages/GraphPage';
import { CvePage } from './pages/CvePage';
import { Remediation } from './pages/Remediation';
import { Validation } from './pages/Validation';
import { Runtime } from './pages/Runtime';
import { Native } from './pages/Native';
import { Obfuscation } from './pages/Obfuscation';
import { DiffTab } from './pages/DiffTab';
import { InvestigationTab } from './pages/InvestigationTab';
import { EvidenceTab } from './pages/EvidenceTab';
import { Assessment } from './pages/Assessment';
import { Search } from './pages/Search';
import { NewAnalysis } from './pages/NewAnalysis';
import { Progress } from './pages/Progress';
import { InvestigationList } from './pages/InvestigationList';
import { InvestigationWorkspace } from './pages/InvestigationWorkspace';
import { DiffWorkspace } from './pages/DiffWorkspace';
import { NotFound } from './pages/NotFound';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'analyses/new', element: <NewAnalysis /> },
      { path: 'progress/execution/:executionId', element: <Progress /> },
      { path: 'progress/analysis/:analysisId', element: <Progress /> },
      { path: 'investigations', element: <InvestigationList /> },
      { path: 'investigations/:investigationId', element: <InvestigationWorkspace /> },
      { path: 'diff/:comparisonId', element: <DiffWorkspace /> },
      {
        path: 'analysis/:analysisId',
        element: <AnalysisLayout />,
        children: [
          { index: true, element: <Overview /> },
          { path: 'findings', element: <Findings /> },
          { path: 'attack-surface', element: <AttackSurface /> },
          { path: 'graph', element: <GraphPage /> },
          { path: 'cve', element: <CvePage /> },
          { path: 'remediation', element: <Remediation /> },
          { path: 'validation', element: <Validation /> },
          { path: 'runtime', element: <Runtime /> },
          { path: 'native', element: <Native /> },
          { path: 'obfuscation', element: <Obfuscation /> },
          { path: 'assessment', element: <Assessment /> },
          { path: 'diff', element: <DiffTab /> },
          { path: 'investigation', element: <InvestigationTab /> },
          { path: 'evidence', element: <EvidenceTab /> },
          { path: 'search', element: <Search /> },
        ],
      },
      { path: '*', element: <NotFound /> },
    ],
  },
]);
