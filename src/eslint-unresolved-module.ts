import type { Rule } from 'eslint';
import type { Node as TsNode, Program } from 'typescript';

/**
 * Rule id of the internal probe. It is never a finding: the adapter turns every
 * report of it into the `type-info-partial` reason and a bounded module list.
 */
export const unresolvedModuleRuleId = 'releaseready/unresolved-module';

interface TypedServices {
  program: Program | null;
  esTreeNodeToTSNodeMap: { get(node: unknown): TsNode | undefined };
}
interface ModuleSource {
  type?: string;
  value?: unknown;
}

const rule: Rule.RuleModule = {
  meta: {
    type: 'problem',
    schema: [],
    messages: { unresolved: '{{name}}' },
    docs: { description: 'Report module specifiers TypeScript cannot resolve' },
  },
  create(context) {
    const services = context.sourceCode.parserServices as
      Partial<TypedServices> | undefined;
    const program = services?.program;
    const map = services?.esTreeNodeToTSNodeMap;
    if (!program || !map) return {};
    const checker = program.getTypeChecker();
    const check = (source: ModuleSource | null | undefined): void => {
      if (source?.type !== 'Literal' || typeof source.value !== 'string')
        return;
      const tsNode = map.get(source);
      if (tsNode && checker.getSymbolAtLocation(tsNode) === undefined)
        context.report({
          node: source as Rule.Node,
          messageId: 'unresolved',
          data: { name: source.value },
        });
    };
    const reference = (node: { source?: ModuleSource | null }): void => {
      check(node.source);
    };
    const listeners: Record<string, (node: never) => void> = {
      // `import './x.css'` binds nothing, so it cannot degrade type information.
      ImportDeclaration: (node: {
        source: ModuleSource;
        specifiers: unknown[];
      }) => {
        if (node.specifiers.length > 0) check(node.source);
      },
      ExportNamedDeclaration: reference,
      ExportAllDeclaration: reference,
      ImportExpression: reference,
      TSExternalModuleReference: (node: { expression: ModuleSource }) => {
        check(node.expression);
      },
    };
    return listeners as Rule.RuleListener;
  },
};

export const releaseready = { rules: { 'unresolved-module': rule } };
export const unresolvedModuleRules = {
  [unresolvedModuleRuleId]: 'error',
} as const;
