import * as vscode from 'vscode';
import * as fs from 'fs';

export class TraceViewerProvider implements vscode.TreeDataProvider<TraceItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<TraceItem | undefined | void> = new vscode.EventEmitter<TraceItem | undefined | void>();
  readonly onDidChangeTreeData: vscode.Event<TraceItem | undefined | void> = this._onDidChangeTreeData.event;

  private traceData: any | null = null;

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  loadTrace(filePath: string): void {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      this.traceData = JSON.parse(content);
      this.refresh();
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to load trace: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  getTreeItem(element: TraceItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TraceItem): Thenable<TraceItem[]> {
    if (!this.traceData) {
      return Promise.resolve([new TraceItem("No trace loaded. Run 'Soroban: Import Execution Trace' to load one.", vscode.TreeItemCollapsibleState.None)]);
    }

    if (!element) {
      const rootItems = [
        new TraceItem(`Contract: ${this.traceData.contract || 'Unknown'}`, vscode.TreeItemCollapsibleState.None),
        new TraceItem(`Function: ${this.traceData.function || 'Unknown'}`, vscode.TreeItemCollapsibleState.None),
        new TraceItem(`Args: ${this.traceData.args || '[]'}`, vscode.TreeItemCollapsibleState.None),
        new TraceItem(`Return Value: ${this.traceData.return_value || 'Unknown'}`, vscode.TreeItemCollapsibleState.None),
      ];

      if (this.traceData.budget) {
        rootItems.push(new TraceItem("Budget", vscode.TreeItemCollapsibleState.Collapsed, "budget"));
      }
      if (this.traceData.storage) {
        rootItems.push(new TraceItem("Storage", vscode.TreeItemCollapsibleState.Collapsed, "storage"));
      }
      if (this.traceData.events && this.traceData.events.length > 0) {
        rootItems.push(new TraceItem(`Events (${this.traceData.events.length})`, vscode.TreeItemCollapsibleState.Collapsed, "events"));
      }
      if (this.traceData.call_sequence && this.traceData.call_sequence.length > 0) {
        rootItems.push(new TraceItem("Call Sequence", vscode.TreeItemCollapsibleState.Collapsed, "calls"));
      }

      return Promise.resolve(rootItems);
    }

    if (element.contextValue === 'budget') {
      const budget = this.traceData.budget;
      return Promise.resolve([
        new TraceItem(`CPU Instructions: ${budget.cpu_instructions || 0}`, vscode.TreeItemCollapsibleState.None),
        new TraceItem(`Memory Bytes: ${budget.memory_bytes || 0}`, vscode.TreeItemCollapsibleState.None)
      ]);
    }

    if (element.contextValue === 'storage') {
      const storage = this.traceData.storage;
      return Promise.resolve(Object.keys(storage).map(k => {
        const valStr = typeof storage[k] === 'object' ? JSON.stringify(storage[k]) : String(storage[k]);
        return new TraceItem(`${k}: ${valStr}`, vscode.TreeItemCollapsibleState.None);
      }));
    }

    if (element.contextValue === 'events') {
      const events = this.traceData.events;
      return Promise.resolve(events.map((e: any, i: number) => {
        const topics = e.topics ? e.topics.join(', ') : '';
        const dataStr = typeof e.data === 'object' ? JSON.stringify(e.data) : String(e.data);
        return new TraceItem(`[${i}] ${topics} -> ${dataStr}`, vscode.TreeItemCollapsibleState.None);
      }));
    }

    if (element.contextValue === 'calls') {
      const calls = this.traceData.call_sequence;
      return Promise.resolve(calls.map((c: any) => {
        const depthPrefix = '-'.repeat(c.depth || 0);
        return new TraceItem(`${depthPrefix} ${c.function}(${c.args || ''})`, vscode.TreeItemCollapsibleState.None);
      }));
    }

    return Promise.resolve([]);
  }
}

class TraceItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue?: string
  ) {
    super(label, collapsibleState);
  }
}

export function registerTraceViewer(context: vscode.ExtensionContext) {
  const traceProvider = new TraceViewerProvider();
  vscode.window.registerTreeDataProvider('soroban-debugger.traceView', traceProvider);

  context.subscriptions.push(
    vscode.commands.registerCommand('soroban-debugger.importTrace', async () => {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Import Trace',
        filters: {
          'Trace JSON': ['json']
        }
      });

      if (uris && uris[0]) {
        traceProvider.loadTrace(uris[0].fsPath);
        vscode.commands.executeCommand('soroban-debugger.traceView.focus');
      }
    })
  );
}