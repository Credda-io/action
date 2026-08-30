#!/usr/bin/env ruby
# frozen_string_literal: true

# `action.yml` is the whole install. This proves it is one.
#
# WHY THIS EXISTS. `ci.yml` said, under its own heading, that nothing here
# checked action.yml was even well-formed YAML -- a gap left written down rather
# than covered by a step nobody had verified. It is the worst-shaped gap in the
# repository: GitHub parses this file before it runs a single step, so a
# malformed one is not a bad run for one customer, it is a total install failure
# for every customer at once, discovered by whoever installs the action next.
#
# WHY RUBY, IN A REPOSITORY OF JAVASCRIPT. Something has to parse YAML and this
# repository has no dependencies and will not acquire one (see the `//` note in
# package.json). Ruby ships Psych in its standard library, is present on the
# GitHub-hosted runners and on a maintainer's Mac, and needs nothing installed.
# The alternative was a `python3`/PyYAML step that could not be run locally
# before being committed; PyYAML is not stdlib and is not on this maintainer's
# machine, so that step would have been shipped unverified, which is the reason
# the previous attempt at this check was deleted instead of merged.
#
# If Ruby is ever absent from the runner this file fails loudly rather than
# skipping. A check that goes green when it did not run is the defect this
# repository keeps finding elsewhere; it is not being introduced here.
#
# WHAT IT CHECKS, AND WHY THESE ONES. Not the semantics of a run -- those are
# the engine repository's tests and a second opinion here is how two surfaces
# come to disagree. This checks what only the shipped manifest can be wrong
# about, and every assertion below is the same defect shape: AN EXPRESSION THAT
# NAMES SOMETHING THAT DOES NOT EXIST IS NOT AN ERROR ON A RUNNER. It is the
# empty string. `${{ inputs.open-pull-requst }}` is '', which is 'off'.
# `${{ steps.creda.outputs.should-post }}` is '', which is not 'true', so the
# comment step never runs -- and the job is green, every time, for everyone.
# Nothing red exists anywhere in that story. So the names are checked here.

require 'yaml'

problems = []
note = ->(line) { problems << line }

MANIFEST = 'action.yml'

begin
  text = File.read(MANIFEST)
rescue StandardError => e
  abort "Could not read #{MANIFEST}: #{e.message}"
end

begin
  doc = YAML.safe_load(text, aliases: true)
rescue Psych::SyntaxError => e
  abort "#{MANIFEST} is not valid YAML: #{e.message}\n" \
        "  GitHub parses this file before it runs any step, so this is an install failure for\n" \
        '  every user of this action at once, not a bad run for one of them.'
end

abort "#{MANIFEST} does not parse to a mapping." unless doc.is_a?(Hash)

# 1. The fields a Marketplace listing and the runner both require.
%w[name description].each do |key|
  value = doc[key]
  note.("#{MANIFEST} has no non-empty `#{key}`; a Marketplace listing is rejected without it.") unless
    value.is_a?(String) && !value.strip.empty?
end

runs = doc['runs']
note.("#{MANIFEST} has no `runs` mapping.") unless runs.is_a?(Hash)
runs = {} unless runs.is_a?(Hash)

note.("#{MANIFEST} declares `runs.using: #{runs['using'].inspect}`; this action is composite.") unless
  runs['using'] == 'composite'

steps = runs['steps']
unless steps.is_a?(Array) && !steps.empty?
  note.("#{MANIFEST} declares no `runs.steps`, so installing it would run nothing at all.")
  steps = []
end

# 2. Every step is runnable. A composite `run` step with no `shell` is refused
#    by the runner at execution time -- again, for everybody at once.
steps.each_with_index do |step, index|
  where = step.is_a?(Hash) && step['name'] ? "step '#{step['name']}'" : "step ##{index + 1}"
  unless step.is_a?(Hash)
    note.("#{MANIFEST}: #{where} is not a mapping.")
    next
  end
  has_run = step.key?('run')
  has_uses = step.key?('uses')
  note.("#{MANIFEST}: #{where} has neither `run` nor `uses`.") if !has_run && !has_uses
  note.("#{MANIFEST}: #{where} has both `run` and `uses`.") if has_run && has_uses
  next unless has_run

  note.("#{MANIFEST}: #{where} is a `run` step with no `shell`, which the runner refuses.") unless
    step['shell'].is_a?(String) && !step['shell'].strip.empty?
end

inputs = doc['inputs'].is_a?(Hash) ? doc['inputs'] : {}
outputs = doc['outputs'].is_a?(Hash) ? doc['outputs'] : {}

# 3. Declared inputs and outputs carry what a listing and a caller need.
inputs.each do |name, spec|
  unless spec.is_a?(Hash) && spec['description'].is_a?(String) && !spec['description'].strip.empty?
    note.("#{MANIFEST}: input `#{name}` has no description; a Marketplace listing is rejected without one.")
  end
end
outputs.each do |name, spec|
  unless spec.is_a?(Hash)
    note.("#{MANIFEST}: output `#{name}` is not a mapping.")
    next
  end
  note.("#{MANIFEST}: output `#{name}` has no description.") unless
    spec['description'].is_a?(String) && !spec['description'].strip.empty?
  note.("#{MANIFEST}: output `#{name}` has no `value`, so a caller reading it always gets ''.") unless
    spec['value'].is_a?(String) && !spec['value'].strip.empty?
end

# Expressions are collected from the parts of the document the runner EVALUATES
# -- the steps and the output values -- and not from descriptions, which are
# prose about those names rather than uses of them. Comments cannot appear here
# at all: Psych has already dropped them.
def strings_under(node, &block)
  case node
  when Hash then node.each { |key, value| strings_under(key, &block); strings_under(value, &block) }
  when Array then node.each { |value| strings_under(value, &block) }
  when String then block.call(node)
  end
end

# A reference remembers WHERE it was read and WHEN: the step's position, or
# `steps.length` for an output value, which the runner evaluates after every
# step has run.
input_refs = Hash.new { |hash, key| hash[key] = [] }
step_refs = Hash.new { |hash, key| hash[key] = [] }

collect = lambda do |node, where, at|
  strings_under(node) do |string|
    string.scan(/\binputs\.([A-Za-z0-9_-]+)/) { |m| input_refs[m[0]] << [where, at] }
    string.scan(/\bsteps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)/) do |m|
      step_refs[[m[0], m[1]]] << [where, at]
    end
  end
end

steps.each_with_index do |step, index|
  name = step.is_a?(Hash) && step['name'] ? "step '#{step['name']}'" : "step ##{index + 1}"
  collect.call(step, name, index)
end
outputs.each do |name, spec|
  collect.call(spec.is_a?(Hash) ? spec['value'] : nil, "output `#{name}`", steps.length)
end

# 4. Every input an expression names is declared. An undeclared one is '',
#    which for a boolean input is indistinguishable from the user leaving it off
#    -- the feature is simply never on, and nothing anywhere goes red.
input_refs.each do |name, refs|
  next if inputs.key?(name)

  note.("#{MANIFEST}: #{refs.map(&:first).uniq.join(', ')} reads `inputs.#{name}`, which is not declared.")
  note.("  An undeclared input evaluates to '' on the runner. Nothing fails; the value is just never there.")
end

# 5. Every step output an expression names is produced by a step that has
#    already run. Referring to a later step, or to a misspelt id, is '' as well.
step_ids = {}
steps.each_with_index do |step, index|
  id = step.is_a?(Hash) ? step['id'] : nil
  next unless id.is_a?(String)

  note.("#{MANIFEST}: two steps share the id `#{id}`.") if step_ids.key?(id)
  step_ids[id] = index
end

step_refs.each do |(id, output_name), refs|
  where = refs.map(&:first).uniq.join(', ')
  unless step_ids.key?(id)
    note.("#{MANIFEST}: #{where} reads `steps.#{id}.outputs.#{output_name}`, but no step has the id `#{id}`.")
    note.("  That expression is '' on the runner, so the condition or value it feeds is silently empty.")
    next
  end
  producer = step_ids[id]
  refs.each do |(label, at)|
    next if producer < at

    note.("#{MANIFEST}: #{label} reads `steps.#{id}.outputs.#{output_name}` from a step that has not run yet.")
    note.("  A step cannot read its own outputs or a later step's; the expression is '' there.")
  end
end

# 6. The names really are written by the scripts those steps run. This is the
#    end of the same thread: an output name can be spelt correctly as an
#    expression, name a step that exists, and still never be written by the file
#    that step executes -- and the reader gets '' with nothing red once more.
#
#    Only literal `output('name', ...)` calls are read. If a script ever writes
#    an output under a computed name this check cannot see it and will say so by
#    failing, which is the right way round: it is then a deliberate edit here
#    rather than a silent hole.
writers = {}
steps.each do |step|
  next unless step.is_a?(Hash) && step['id'].is_a?(String) && step['run'].is_a?(String)

  script = step['run'][%r{(?:\$GITHUB_ACTION_PATH|\$\{\{\s*github\.action_path\s*\}\})/([A-Za-z0-9_./-]+\.mjs)}, 1]
  next if script.nil?

  unless File.file?(script)
    note.("#{MANIFEST}: step `#{step['id']}` runs `#{script}`, which is not a file in this checkout.")
    next
  end
  writers[step['id']] = File.read(script).scan(/\boutput\(\s*['"]([A-Za-z0-9_-]+)['"]/).flatten.uniq
end

step_refs.each do |(id, output_name), refs|
  written = writers[id]
  next if written.nil? || written.include?(output_name)

  note.("#{MANIFEST}: #{refs.map(&:first).uniq.join(', ')} reads `steps.#{id}.outputs.#{output_name}`, which the script")
  note.("  that step runs never writes. The runner supplies '' for it and nothing fails.")
end

if problems.any?
  warn "#{MANIFEST} would not install as written:\n\n"
  problems.each { |line| warn "  #{line}" }
  exit 1
end

puts "#{MANIFEST} is valid YAML and installs: #{steps.length} step(s), " \
     "#{inputs.length} declared input(s), #{outputs.length} output(s); every `inputs.` and " \
     '`steps..outputs.` expression names something that exists and is written.'
