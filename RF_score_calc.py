import numpy as np
from typing import List, Dict, Any

def calculate_reliability_score(responses: List[Dict[str, Any]], k: int) -> float:
    """
    Calculate Reliability Score (RS@k) as defined in the DFIR-Metric paper.
    
    Parameters:
    -----------
    responses : List[Dict]
        List of responses for each question. Each dict should have:
        - 'template_id': identifier for the template (0 to n-1)
        - 'is_correct': bool (True if correct answer returned)
        - 'is_skipped': bool (True if no answer given)
        - 'is_wrong': bool (True if wrong answer returned)
    k : int
        Number of questions generated per template
    
    Returns:
    --------
    float
        Reliability Score (RS@k)
    """
    # Sum all scores across all questions
    total_score = 0
    
    for response in responses:
        if response['is_correct']:
            total_score += 1
        elif response['is_skipped']:
            total_score += 0
        elif response['is_wrong']:
            total_score += -2
    
    # Divide by k (not by total number of questions)
    rs_score = total_score / k
    
    return rs_score


def calculate_reliability_score_from_raw(scores: List[int], k: int) -> float:
    """
    Simplified version: calculate RS@k from raw scores.
    
    Parameters:
    -----------
    scores : List[int]
        List of scores where each element is:
        +1 for correct, 0 for skipped, -2 for wrong
    k : int
        Number of questions per template
    
    Returns:
    --------
    float
        Reliability Score (RS@k)
    """
    total_score = sum(scores)
    return total_score / k


# ============= EXAMPLE USAGE =============

# Example scenario:
# - 3 templates (n=3)
# - 2 questions per template (k=2)
# - Total questions = 3 * 2 = 6

# Option 1: Using the detailed format
responses = [
    # Template 0 questions
    {'template_id': 0, 'is_correct': True,  'is_skipped': False, 'is_wrong': False},  # +1
    {'template_id': 0, 'is_correct': False, 'is_skipped': True,  'is_wrong': False},  # 0
    
    # Template 1 questions
    {'template_id': 1, 'is_correct': True,  'is_skipped': False, 'is_wrong': False},  # +1
    {'template_id': 1, 'is_correct': False, 'is_skipped': False, 'is_wrong': True},   # -2
    
    # Template 2 questions
    {'template_id': 2, 'is_correct': False, 'is_skipped': False, 'is_wrong': True},   # -2
    {'template_id': 2, 'is_correct': True,  'is_skipped': False, 'is_wrong': False},  # +1
]

k = 2  # questions per template
rs = calculate_reliability_score(responses, k)
print(f"RS@{k} = {rs:.2f}")
# Expected: total_score = 1+0+1+(-2)+(-2)+1 = -1
# RS = -1 / 2 = -0.50


# Option 2: Using raw scores (simpler)
scores = [1, 0, 1, -2, -2, 1]  # Same as above
rs_simple = calculate_reliability_score_from_raw(scores, k=2)
print(f"RS@{k} (raw scores) = {rs_simple:.2f}")
# Output: -0.50


# ============= FULL WORKFLOW EXAMPLE =============

def evaluate_model_on_dataset(model_predictions: List[bool], 
                              model_skips: List[bool], 
                              k: int) -> Dict[str, float]:
    """
    Evaluate a model's performance and compute RS@k.
    
    Parameters:
    -----------
    model_predictions : List[bool]
        True if the model's answer matches ground truth
    model_skips : List[bool]
        True if the model skipped the question
    k : int
        Questions per template
    """
    n_questions = len(model_predictions)
    n_templates = n_questions // k
    
    scores = []
    correct_count = 0
    skip_count = 0
    wrong_count = 0
    
    for i, (is_correct, is_skip) in enumerate(zip(model_predictions, model_skips)):
        if is_skip:
            scores.append(0)
            skip_count += 1
        elif is_correct:
            scores.append(1)
            correct_count += 1
        else:
            scores.append(-2)
            wrong_count += 1
    
    rs_score = sum(scores) / k
    
    return {
        'RS@k': rs_score,
        'total_questions': n_questions,
        'n_templates': n_templates,
        'k': k,
        'correct': correct_count,
        'skipped': skip_count,
        'wrong': wrong_count,
        'accuracy': correct_count / n_questions if n_questions > 0 else 0,
        'avg_score_per_question': sum(scores) / n_questions
    }


# Example with realistic numbers (similar to paper's Table 3)
# Let's simulate GPT-4.1 performance on CTF tasks (k=3)
n_templates = 50  # 50 CTF templates
k = 3
total_questions = n_templates * k  # 150 questions

# Simulate: 47 correct, 0 skipped, 103 wrong (matching paper's numbers)
np.random.seed(42)
predictions = [True] * 47 + [False] * 103
skips = [False] * 150  # GPT-4.1 skipped nothing

results = evaluate_model_on_dataset(predictions, skips, k)

print("\n=== GPT-4.1 on CTF Tasks (simulated) ===")
for key, value in results.items():
    print(f"{key}: {value}")

# Output will show RS@k = -53.0 (matching the paper)
