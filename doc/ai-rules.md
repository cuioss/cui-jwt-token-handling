# AI Development Guidelines

This file provides guidance to AI tools (IntelliJ Junie, Claude Code, GitHub Copilot, etc.) when working with code in CUI projects.

## Configuration

**Standards Base URL**: Configure this based on your development environment:
- **Remote (gitingest)**: `https://gitingest.com/github.com/cuioss/cui-llm-rules/tree/main`
- **Local checkout**: Use relative path to your local standards directory (e.g., `../cui-llm-rules`)

Replace `{STANDARDS_BASE_URL}` in all references below with your chosen base URL.

## Core Process Rules (CRITICAL - READ FIRST)
**Reference**: `{STANDARDS_BASE_URL}/standards/process/general.adoc`

These rules govern ALL development activities:

1. **If in doubt, ask the user** - Never make assumptions
2. **Always research topics** - Use available tools (WebSearch, WebFetch, etc.) to find the most recent best practices
3. **Never guess or be creative** - If you cannot find best practices, ask the user
4. **Do not proliferate documents** - Always use context-relevant documents, never create without user approval
5. **Never add dependencies without approval** - Always ask before adding any dependency

## Task Completion Standards (MANDATORY)
**Reference**: `{STANDARDS_BASE_URL}/standards/process/task-completion-standards.adoc`

### Pre-Commit Checklist
Execute in sequence before ANY commit:

1. **Quality Verification**: `./mvnw -Ppre-commit clean verify -DskipTests`
   - Fix ALL errors and warnings (mandatory)
   - Address code quality, formatting, and linting issues

2. **Final Verification**: `./mvnw clean install`
   - Must complete without errors or warnings
   - All tests must pass
   - Tasks are complete ONLY after this succeeds

3. **Documentation**: Update if changes affect APIs, features, or configuration

4. **Commit Message**: Follow Git Commit Standards

### Quality Requirements
- New code requires appropriate test coverage
- Existing tests must continue to pass
- Documentation must be updated for API/feature changes
- Link commits to relevant issues or tasks

## Build Commands Template
Common Maven commands for CUI projects:
- Build project: `./mvnw clean install`
- Build Single Module: `./mvnw clean install -pl <module-name>`
- Run tests: `./mvnw test`
- Run single test: `./mvnw test -Dtest=ClassName#methodName`
- Clean-Up Code: `./mvnw -Ppre-commit clean install -DskipTests` -> Check the console after running the command and fix all errors and warnings, verify until they are all corrected

## CUI Standards Documentation
- Standards Overview: `{STANDARDS_BASE_URL}/standards`

### Java Standards
- Java Code Standards: `{STANDARDS_BASE_URL}/standards/java`
- DSL-Style Constants: `{STANDARDS_BASE_URL}/standards/java/dsl-style-constants.adoc`

### Documentation Standards
- General Documentation: `{STANDARDS_BASE_URL}/standards/documentation`
- Javadoc Standards: `{STANDARDS_BASE_URL}/standards/documentation/javadoc-standards.adoc`
- AsciiDoc Standards: `{STANDARDS_BASE_URL}/standards/documentation/asciidoc-standards.adoc`
- README Structure: `{STANDARDS_BASE_URL}/standards/documentation/readme-structure.adoc`

### Logging Standards
- Logging Core Standards: `{STANDARDS_BASE_URL}/standards/logging`
- Logging Implementation Guide: `{STANDARDS_BASE_URL}/standards/logging/implementation-guide.adoc`
- Logging Testing Guide: `{STANDARDS_BASE_URL}/standards/logging/testing-guide.adoc`

### Testing Standards
- Testing Core Standards: `{STANDARDS_BASE_URL}/standards/testing`
- Quality Standards: `{STANDARDS_BASE_URL}/standards/testing/quality-standards.adoc`
- CUI Test Generator Guide: `https://gitingest.com/github.com/cuioss/cui-test-generator` (separate repository)

### Requirements Standards
- Requirements Documents: `{STANDARDS_BASE_URL}/standards/requirements`
- Specification Documents: `{STANDARDS_BASE_URL}/standards/requirements/specification-documents.adoc`
- New Project Guide: `{STANDARDS_BASE_URL}/standards/requirements/new-project-guide.adoc`

### CDI and Quarkus Standards
- CDI Development Patterns: `{STANDARDS_BASE_URL}/standards/cdi-quarkus`
- Quarkus Testing Standards: `{STANDARDS_BASE_URL}/standards/cdi-quarkus/testing-standards.adoc`
- Container Standards: `{STANDARDS_BASE_URL}/standards/cdi-quarkus/container-standards.adoc`

## Code Style Guidelines
**Reference**: `{STANDARDS_BASE_URL}/standards/java`

### Language Standards
- Use latest Java LTS version features (Java 17+ minimum)
- Use records for data carriers and DTOs
- Use switch expressions over classic switch statements
- Use text blocks for multi-line strings
- Use var for local variables with obvious types
- Use sealed classes for restricted hierarchies
- Pattern matching in instanceof and switch
- Stream API for complex data transformations
- Use proper access modifiers (prefer package-private over public)
- Mark classes final unless designed for inheritance
- Prefer composition over inheritance
- Return empty collections instead of null
- Use Optional for nullable return values
- Use DSL-style nested constants for logging messages
- Follow builder pattern for complex object creation
- Implement fluent interfaces where appropriate
- Use method references over lambdas when possible
- Keep lambda expressions short and clear
- Avoid side effects in streams
- Use immutable objects when possible
- Make fields final by default
- Use enum instead of constants for fixed sets
- Prefer immutable collections (List.of(), Set.of())
- Avoid magic numbers, use named constants
- Use StringBuilder for string concatenation in loops
- Override toString() for debugging
- Implement equals() and hashCode() together
- Use @Override annotation consistently
- Avoid premature optimization
- See Lombok Usage section for annotation patterns

## Lombok Usage
**Reference**: `{STANDARDS_BASE_URL}/standards/java/java-code-standards.adoc`
- Use `@Builder` for complex object creation
- Use `@Value` for immutable objects
- Use `@NonNull` for required parameters
- Use `@ToString` and `@EqualsAndHashCode` for value objects
- Use `@UtilityClass` for utility classes
- Make proper use of `lombok.config` settings

## Logging Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/logging`
- Use `de.cuioss.tools.logging.CuiLogger` (private static final LOGGER)
- Logger must be private static final with constant name 'LOGGER'
- Module/artifact: cui-java-tools
- Exception parameter always comes first in logging methods
- Use '%s' for string substitutions (not '{}' or '%d')
- Use `de.cuioss.tools.logging.LogRecord` for template logging
- Follow logging level ranges: INFO (001-99), WARN (100-199), ERROR (200-299), FATAL (300-399)
- All log messages must be documented in doc/LogMessages.adoc
- No log4j, slf4j, System.out, or System.err usage

## Testing Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/testing`
- Use JUnit 5 (`@Test`, `@DisplayName`, `@Nested`)
- Follow AAA pattern (Arrange-Act-Assert)
- One logical assertion per test
- Tests must be independent and not rely on execution order
- Minimum 80% line and branch coverage
- Use Maven profile `-Pcoverage` for coverage verification
- All public APIs must be tested
- Use cui-test-juli-logger for logger testing with `@EnableTestLogger`
- Use assertLogMessagePresentContaining for testing log messages
- Critical paths must have 100% coverage
- Forbidden: Mockito, PowerMock, Hamcrest - use CUI alternatives

## CUI Test Generator Usage
**Reference**: `https://gitingest.com/github.com/cuioss/cui-test-generator` (separate repository)
- Mandatory for all test data generation in CUI projects
- Primary framework for creating test objects and data
- Provides type-safe, consistent test data generation
- Use cui-test-value-objects for value object contract testing
- Integrates with parameterized tests via @GeneratorsSource
- See Parameterized Tests Standards for annotation hierarchy

## Parameterized Tests Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/testing/quality-standards.adoc#parameterized-tests-best-practices`
- **Mandatory** for 3+ similar test variants
- Annotation hierarchy (preferred order):
  1. `@GeneratorsSource` - Most preferred for complex objects
  2. `@CompositeTypeGeneratorSource` - For multiple related types
  3. `@CsvSource` - Standard choice for simple data
  4. `@ValueSource` - Single parameter variations
  5. `@MethodSource` - Last resort only
- Use `@ParameterizedTest` with `@DisplayName`
- Consolidate duplicate test methods
- Provide clear test data and expected outcomes
- Document why @MethodSource if used

## Javadoc Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/documentation/javadoc-standards.adoc`
- Every public and protected class/interface must be documented
- Include clear purpose statement in class documentation
- Document all public methods with parameters, returns, and exceptions
- Include `@since` tag with version information
- Document thread-safety considerations
- Include usage examples for complex classes and methods
- Every package must have package-info.java
- Use `{@link}` for references to classes, methods, and fields
- Document Builder classes with complete usage examples

## CDI and Quarkus Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/cdi-quarkus`
- Use constructor injection (mandatory over field injection)
- Single constructor rule: No `@Inject` needed for single constructors
- Use `final` fields for injected dependencies
- Use `@ApplicationScoped` for stateless services
- Use `@QuarkusTest` for CDI context testing
- Use `@QuarkusIntegrationTest` for packaged app testing
- Container: Use Quarkus distroless base image (91.9MB)
- HTTPS required for all integration tests
- OWASP Docker Top 10 compliance mandatory

## CSS Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/css`
- Use CSS custom properties (variables) for theming
- Follow BEM methodology for class naming
- Use Stylelint for code quality enforcement
- Use Prettier for consistent formatting
- Mobile-first responsive design approach
- Semantic HTML with accessible CSS patterns
- Performance optimization: minimize CSS bundle size
- Support for modern browsers (last 2 versions)

## JavaScript Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/javascript`
- Use ES6+ modern JavaScript features
- Use ESLint with strict configuration
- Use Prettier for code formatting
- Use Jest for unit testing framework
- Follow functional programming patterns when appropriate
- Use JSDoc for comprehensive documentation
- Use Lit components for web components (Quarkus DevUI context)
- Maven integration via frontend-maven-plugin
- Cypress for E2E testing

## Documentation Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/documentation`
- Use AsciiDoc format with `.adoc` extension
- Include proper document header with TOC and section numbering
- Use `:source-highlighter: highlight.js` attribute
- Use `xref:` syntax for cross-references (not `<<>>`)
- Blank lines required before all lists
- Consistent heading hierarchy
- Update main README when adding new documents
- Reference AsciiDoc standards from all relevant documents

## Process Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/process`
- Follow standardized git commit message format
- Use structured refactoring process for code improvements
- Complete task completion standards for quality assurance
- Maintain Javadoc error resolution process
- Follow Java test maintenance procedures
- Implement logger maintenance standards compliance
- If in doubt, ask the user - never guess or be creative
- Always research topics using available tools

## Requirements Standards
**Reference**: `{STANDARDS_BASE_URL}/standards/requirements`
- All requirements must be traceable to specifications
- Requirements must be specific, measurable, achievable, relevant, time-bound
- Maintain consistent documentation structure across projects
- Link implemented specifications to actual implementation code
- Use standard directory structure: doc/Requirements.adoc, doc/Specification.adoc
- Update specifications when implementation is complete
- See Documentation Standards for AsciiDoc formatting rules

## AI Tool Specific Instructions

### For IntelliJ Junie
- Always check for pre-commit profile availability
- Use proper Maven module selection for focused builds
- Leverage IDE integration for testing and debugging

### For Claude Code
- Use todo lists for complex multi-step tasks
- Batch tool calls for parallel operations
- Always run lint and typecheck commands after code changes

### For GitHub Copilot
- Context-aware suggestions based on CUI standards
- Follow established patterns in the codebase
- Respect existing code style and architecture

### For All AI Tools
- Always refer to CUI standards documentation before making changes
- Validate against existing patterns in the codebase
- Run tests after any code modifications
- Follow the pre-commit process for code quality
- Document any new public APIs according to Javadoc standards
- Use gitingest.com links for accessing CUI standards repository content
